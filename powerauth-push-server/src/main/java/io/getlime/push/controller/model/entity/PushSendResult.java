package io.getlime.push.controller.model.entity;

/**
 * Created by petrdvorak on 06/11/2016.
 */
public class PushSendResult {

    public class iOS {

        private int sent;
        private int failed;
        private int total;

        public int getSent() {
            return sent;
        }

        public void setSent(int sent) {
            this.sent = sent;
        }

        public int getFailed() {
            return failed;
        }

        public void setFailed(int failed) {
            this.failed = failed;
        }

        public int getTotal() {
            return total;
        }

        public void setTotal(int total) {
            this.total = total;
        }
    }

    public class Android {

        private int sent;
        private int failed;
        private int total;

        public int getSent() {
            return sent;
        }

        public void setSent(int sent) {
            this.sent = sent;
        }

        public int getFailed() {
            return failed;
        }

        public void setFailed(int failed) {
            this.failed = failed;
        }

        public int getTotal() {
            return total;
        }

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

    public Android getAndroid() {
        return android;
    }

    public iOS getIos() {
        return ios;
    }

}
