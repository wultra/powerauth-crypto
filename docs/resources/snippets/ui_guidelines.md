## Interpretation of Activation Status in UI

After the application decrypts and decodes the status blob, it needs to react to the information appropriately.

### The Login Screen

The first screen that interacts with the activation status is the screen that is used for login - generally the first screen after the app launch. This screen should implement following logic:

1) Check if there is any activation stored on the device.
2) In case there is an activation, obtain the activation status (call `/pa/activation/status` endpoint), decrypt and decode it.
3) Look at the activation state property:
    - `CREATED`, `OTP_USED`, `REMOVED` - Generally, these are states that you can safely interpret as "There is no activation in current progress." Display a UI that enables a [new device activation](./Activation).
    - `BLOCKED` - In case you provide a mechanism to unblock the activation, for example via the Internet banking, show a wizard that explains how to unblock the device. In case you have no such mechanism, interpret this state just as if the activation was in `REMOVED` state and show UI for a [new device activation](./Activation).
    - `ACTIVE` - Display a UI that enables user login.

### The PIN / Password Screen

The first thing that the screen that allows user to enter the PIN code or password should do it to ask for an activation status. As a response, it receives the number of failed attempts and maximum allowed number of failed attempts.

In case failed attempt count is non-zero, UI should display information about remaining attempts. Remaining attempts can be calculated as the difference between maximum allowed failed attempts and current number of failed attempts. In case failed attempts is zero, there is no indication of remaining attempts count.

In case user enters a PIN code or password for the purpose of authentication, server should responde with the authentication result, that is generally in the format of yes/no response. In case the authentication was not successful, client should ask for the activation status again. In case activation remains active, it should just report authentication error and display remaining attempt count. In case activation was blocked or removed, PIN screen should be closed, application should log user out and display an information about the current activation status.
