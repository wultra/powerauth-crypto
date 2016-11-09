package io.getlime.push.controller.model.entity;

/**
 * Class that contains push message sending result data.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PushSendResult {

    public class iOS {

        private int sent;
        private int failed;
        private int total;

        /**
         * Get number of messages that were sent successfully.
         * @return Number of sent messages.
         */
        public int getSent() {
            return sent;
        }

        /**
         * Set number of messages that were sent successfully.
         * @param sent Number of sent messages.
         */
        public void setSent(int sent) {
            this.sent = sent;
        }

        /**
         * Get number of messages that were sent with failure.
         * @return Number of failed messages.
         */
        public int getFailed() {
            return failed;
        }

        /**
         * Set number of messages that were sent with failure.
         * @param failed Number of failed messages.
         */
        public void setFailed(int failed) {
            this.failed = failed;
        }

        /**
         * Get total number of messages that were attempted to send.
         * @return Total number of messages.
         */
        public int getTotal() {
            return total;
        }

        /**
         * Set total number of messages that were attempted to send.
         * @param total Total number of messages.
         */
        public void setTotal(int total) {
            this.total = total;
        }
    }

    public class Android {

        private int sent;
        private int failed;
        private int total;

        /**
         * Get number of messages that were sent successfully.
         * @return Number of sent messages.
         */
        public int getSent() {
            return sent;
        }

        /**
         * Set number of messages that were sent successfully.
         * @param sent Number of sent messages.
         */
        public void setSent(int sent) {
            this.sent = sent;
        }

        /**
         * Get number of messages that were sent with failure.
         * @return Number of failed messages.
         */
        public int getFailed() {
            return failed;
        }

        /**
         * Set number of messages that were sent with failure.
         * @param failed Number of failed messages.
         */
        public void setFailed(int failed) {
            this.failed = failed;
        }

        /**
         * Get total number of messages that were attempted to send.
         * @return Total number of messages.
         */
        public int getTotal() {
            return total;
        }

        /**
         * Set total number of messages that were attempted to send.
         * @param total Total number of messages.
         */
        public void setTotal(int total) {
            this.total = total;
        }
    }

    private iOS ios;
    private Android android;

    public PushSendResult() {
        this.ios = new iOS();
        this.android = new Android();
    }

    /**
     * Data associated with push messages sent to Android devices.
     */
    public Android getAndroid() {
        return android;
    }

    /**
     * Data associated with push messages sent to iOS devices.
     */
    public iOS getIos() {
        return ios;
    }

}
