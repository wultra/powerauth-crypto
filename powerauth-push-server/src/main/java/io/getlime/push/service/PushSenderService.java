package io.getlime.push.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.relayrides.pushy.apns.*;
import com.relayrides.pushy.apns.util.ApnsPayloadBuilder;
import com.relayrides.pushy.apns.util.SimpleApnsPushNotification;
import com.relayrides.pushy.apns.util.TokenUtil;
import io.getlime.push.controller.model.entity.PushMessage;
import io.getlime.push.controller.model.entity.PushSendResult;
import io.getlime.push.repository.AppCredentialsRepository;
import io.getlime.push.repository.DeviceRegistrationRepository;
import io.getlime.push.repository.PushMessageRepository;
import io.getlime.push.repository.model.AppCredentials;
import io.getlime.push.repository.model.DeviceRegistration;
import io.getlime.push.repository.model.PushMessageEntity;
import io.getlime.push.service.fcm.FcmNotification;
import io.getlime.push.service.fcm.FcmSendRequest;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.concurrent.ListenableFuture;
import org.springframework.util.concurrent.ListenableFutureCallback;
import org.springframework.web.client.AsyncRestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Phaser;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class responsible for sending push notifications to APNs service.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Service
public class PushSenderService {

    private AppCredentialsRepository appCredentialsRepository;
    private DeviceRegistrationRepository deviceRegistrationRepository;
    private PushMessageRepository pushMessageRepository;

    /**
     * Constructor that autowires required repositories.
     * @param appCredentialsRepository Repository with app credentials.
     * @param deviceRegistrationRepository Repository with device registrations.
     * @param pushMessageRepository Repository with logged push messages.
     */
    @Autowired
    public PushSenderService(AppCredentialsRepository appCredentialsRepository, DeviceRegistrationRepository deviceRegistrationRepository, PushMessageRepository pushMessageRepository) {
        this.appCredentialsRepository = appCredentialsRepository;
        this.deviceRegistrationRepository = deviceRegistrationRepository;
        this.pushMessageRepository = pushMessageRepository;
    }

    /**
     * Send push notifications to given application.
     * @param appId App ID used for addressing push messages. Required so that appropriate APNs/FCM credentials can be obtained.
     * @param pushMessageList List with push message objects.
     * @return Result of this batch sending.
     * @throws InterruptedException In case sending is interrupted.
     * @throws IOException In case certificate data cannot be read.
     */
    public PushSendResult send(Long appId, List<PushMessage> pushMessageList) throws InterruptedException, IOException {

        // Get APNs and FCM credentials
        AppCredentials credentials = this.appCredentialsRepository.findFirstByAppId(appId);

        // Prepare and connect APNs client
        final String iosTopic = credentials.getIosBundle();
        final ApnsClient apnsClient = new ApnsClientBuilder()
                .setClientCredentials(new ByteArrayInputStream(credentials.getIos()), credentials.getIosPassword())
                .build();
        final Future<Void> connectFuture = apnsClient.connect(ApnsClient.DEVELOPMENT_APNS_HOST);
        connectFuture.await();

        // Prepare and connect FCM client
        final AsyncRestTemplate restTemplate = new AsyncRestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "key=" + credentials.getAndroid());

        // Prepare a phaser for async sending synchronization
        final Phaser phaser = new Phaser(1);

        // Prepare a result object
        final PushSendResult result = new PushSendResult();

        // Send push message batch
        for (PushMessage pushMessage : pushMessageList) {

            // Get the message user ID
            String userId = pushMessage.getUserId();
            if (userId == null || userId.isEmpty()) {
                throw new IllegalArgumentException("No userId was specified");
            }

            // Get user device registrations
            String activationId = pushMessage.getActivationId();
            List<DeviceRegistration> registrations;
            if (activationId != null) { // in case the message should go to the specific device
                registrations = deviceRegistrationRepository.findByUserIdAndAppIdAndActivationId(userId, appId, activationId);
            } else {
                registrations = deviceRegistrationRepository.findByUserIdAndAppId(userId, appId);
            }

            // Send push messages to given devices
            for (final DeviceRegistration registration : registrations) {

                // Store the message in the database
                final PushMessageEntity sentMessage = this.storePushMessageInDatabase(pushMessage, registration.getId());

                // Check if given push is not personal, or if it is, that registration is in active state.
                // This avoids sending personal notifications to registrations that are blocked or removed.
                if (!pushMessage.getPersonal() || registration.getActive()) {

                    phaser.register();

                    // Send a push message to the provided mobile platform.
                    String platform = registration.getPlatform();
                    if (platform.equals(DeviceRegistration.Platform.iOS)) { // iOS - APNs

                        final String token = TokenUtil.sanitizeTokenString(registration.getPushToken());
                        final String payload = buildApnsPayload(pushMessage);
                        Date validUntil = pushMessage.getMessage().getValidUntil();

                        final SimpleApnsPushNotification pushNotification = new SimpleApnsPushNotification(token, iosTopic, payload, validUntil, DeliveryPriority.IMMEDIATE, pushMessage.getMessage().getCollapseKey());

                        final Future<PushNotificationResponse<SimpleApnsPushNotification>> sendNotificationFuture = apnsClient.sendNotification(pushNotification);

                        sendNotificationFuture.addListener(new GenericFutureListener<Future<PushNotificationResponse<SimpleApnsPushNotification>>>() {

                            @Override
                            public void operationComplete(Future<PushNotificationResponse<SimpleApnsPushNotification>> future) throws Exception {
                                try {
                                    final PushNotificationResponse<SimpleApnsPushNotification> pushNotificationResponse = future.get();

                                    result.getIos().setTotal(result.getIos().getTotal() + 1);

                                    if (pushNotificationResponse != null) {
                                        if (!pushNotificationResponse.isAccepted()) {
                                            Logger.getLogger(PushSenderService.class.getName()).log(Level.SEVERE, "Notification rejected by the APNs gateway: " + pushNotificationResponse.getRejectionReason());
                                            sentMessage.setStatus(PushMessageEntity.Status.FAILED);
                                            pushMessageRepository.save(sentMessage);

                                            result.getIos().setFailed(result.getIos().getFailed() + 1);

                                            if (pushNotificationResponse.getRejectionReason().equals("BadDeviceToken")) {
                                                deviceRegistrationRepository.delete(registration);
                                                Logger.getLogger(PushSenderService.class.getName()).log(Level.SEVERE, "\t... due to bad device token value.");
                                            }

                                            if (pushNotificationResponse.getTokenInvalidationTimestamp() != null) {
                                                deviceRegistrationRepository.delete(registration);
                                                Logger.getLogger(PushSenderService.class.getName()).log(Level.SEVERE, "\t... and the token is invalid as of " + pushNotificationResponse.getTokenInvalidationTimestamp());
                                            }
                                        } else {
                                            sentMessage.setStatus(PushMessageEntity.Status.SENT);
                                            pushMessageRepository.save(sentMessage);
                                            result.getIos().setSent(result.getIos().getSent() + 1);
                                        }
                                    } else {
                                        Logger.getLogger(PushSenderService.class.getName()).log(Level.SEVERE, "Notification rejected by the APNs gateway: unknown error, will retry");
                                        sentMessage.setStatus(PushMessageEntity.Status.PENDING);
                                        pushMessageRepository.save(sentMessage);
                                    }
                                } catch (final ExecutionException e) {
                                    if (e.getCause() instanceof ClientNotConnectedException) {
                                        apnsClient.getReconnectionFuture().await();
                                    }
                                } finally {
                                    phaser.arriveAndDeregister();
                                }
                            }

                        });

                    } else if (platform.equals(DeviceRegistration.Platform.Android)) { // Android - FCM

                        final String fcmSendUrl = "https://fcm.googleapis.com/fcm/send";

                        FcmSendRequest request = new FcmSendRequest();
                        request.setTo(registration.getPushToken());
                        request.setData(pushMessage.getMessage().getExtras());
                        request.setCollapseKey(pushMessage.getMessage().getCollapseKey());

                        if (!pushMessage.getSilent()) {
                            FcmNotification notification = new FcmNotification();
                            notification.setTitle(pushMessage.getMessage().getTitle());
                            notification.setBody(pushMessage.getMessage().getBody());
                            notification.setSound(pushMessage.getMessage().getSound());
                            notification.setTag(pushMessage.getMessage().getCollapseKey());
                            request.setNotification(notification);
                        }

                        HttpEntity<FcmSendRequest> entity = new HttpEntity<>(request, headers);
                        final ListenableFuture<ResponseEntity<String>> future = restTemplate.exchange(fcmSendUrl, HttpMethod.POST, entity, String.class);
                        result.getAndroid().setTotal(result.getAndroid().getTotal() + 1);
                        future.addCallback(new ListenableFutureCallback<ResponseEntity<String>>() {
                            @Override
                            public void onFailure(Throwable throwable) {
                                sentMessage.setStatus(PushMessageEntity.Status.FAILED);
                                pushMessageRepository.save(sentMessage);
                                result.getAndroid().setFailed(result.getAndroid().getFailed() + 1);
                                Logger.getLogger(PushSenderService.class.getName()).log(Level.SEVERE, "Notification rejected by the FCM gateway:" + throwable.getLocalizedMessage());
                                Logger.getLogger(PushSenderService.class.getName()).log(Level.INFO, throwable.getLocalizedMessage());
                                phaser.arriveAndDeregister();
                            }

                            @Override
                            public void onSuccess(ResponseEntity<String> stringResponseEntity) {
                                sentMessage.setStatus(PushMessageEntity.Status.SENT);
                                pushMessageRepository.save(sentMessage);
                                result.getAndroid().setSent(result.getAndroid().getSent() + 1);
                                phaser.arriveAndDeregister();
                            }
                        });

                    }
                }
            }

        }

        phaser.arriveAndAwaitAdvance();

        return result;
    }

    /**
     * Stores a push message in the database table `push_message`.
     * @param pushMessage Push message to be stored.
     * @param registrationId Device registration ID to be used for this message.
     * @return New database entity with push message information.
     * @throws JsonProcessingException In case message body JSON serialization fails.
     */
    private PushMessageEntity storePushMessageInDatabase(PushMessage pushMessage, Long registrationId) throws JsonProcessingException {
        // Store the message in database
        PushMessageEntity entity = new PushMessageEntity();
        entity.setDeviceRegistrationId(registrationId);
        entity.setUserId(pushMessage.getUserId());
        entity.setActivationId(pushMessage.getActivationId());
        entity.setEncrypted(pushMessage.getEncrypted());
        entity.setPersonal(pushMessage.getPersonal());
        entity.setSilent(pushMessage.getSilent());
        entity.setStatus(PushMessageEntity.Status.PENDING);
        entity.setTimestampCreated(new Date());
        ObjectMapper mapper = new ObjectMapper();
        String messageBody = mapper.writeValueAsString(pushMessage.getMessage());
        entity.setMessageBody(messageBody);
        return pushMessageRepository.save(entity);
    }

    /**
     * Method to build APNs message payload.
     * @param push Push message object with APNs data.
     * @return String with APNs JSON payload.
     */
    private String buildApnsPayload(PushMessage push) {
        final ApnsPayloadBuilder payloadBuilder = new ApnsPayloadBuilder();
        payloadBuilder.setAlertTitle(push.getMessage().getTitle());
        payloadBuilder.setAlertBody(push.getMessage().getBody());
        payloadBuilder.setBadgeNumber(push.getMessage().getBadge());
        payloadBuilder.setCategoryName(push.getMessage().getCategory());
        payloadBuilder.setSoundFileName(push.getMessage().getSound());
        payloadBuilder.setContentAvailable(push.getSilent());
        payloadBuilder.addCustomProperty("thread-id", push.getMessage().getCollapseKey());
        Map<String, Object> extras = push.getMessage().getExtras();
        if (extras != null) {
            for (String key : extras.keySet()) {
                payloadBuilder.addCustomProperty(key, extras.get(key));
            }
        }
        return payloadBuilder.buildWithDefaultMaximumLength();
    }

}
