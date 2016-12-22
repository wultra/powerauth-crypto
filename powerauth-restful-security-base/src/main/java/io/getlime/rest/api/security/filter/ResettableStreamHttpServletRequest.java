/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.rest.api.security.filter;

import com.google.common.io.ByteStreams;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.util.Arrays;

/**
 * Resettable HTTP servlet request stream.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public class ResettableStreamHttpServletRequest extends HttpServletRequestWrapper {

    private byte[] requestBody = new byte[0];
    private boolean bufferFilled = false;

    /**
     * Constructs a request object wrapping the given request.
     *
     * @param request The request to wrap
     * @throws IllegalArgumentException if the request is null
     */
    public ResettableStreamHttpServletRequest(HttpServletRequest request) {
        super(request);
    }

    /**
     * Get request body.
     * @return Bytes with the request body contents.
     * @throws IOException In case stream reqding fails.
     */
    public byte[] getRequestBody() throws IOException {

        if (bufferFilled) {
            return Arrays.copyOf(requestBody, requestBody.length);
        }

        InputStream inputStream = super.getInputStream();

        requestBody = ByteStreams.toByteArray(inputStream);

        bufferFilled = true;

        return requestBody;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return new CustomServletInputStream(getRequestBody());
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }

    private static class CustomServletInputStream extends ServletInputStream {

        private ByteArrayInputStream buffer;

        public CustomServletInputStream(byte[] contents) {
            this.buffer = new ByteArrayInputStream(contents);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            return buffer.read(b, off, len);
        }

        @Override
        public int readLine(byte[] b, int off, int len) throws IOException {
            // Copy-paste from ServletInputStream code, just replaced 'this' with 'buffer'.
            if(len <= 0) {
                return 0;
            } else {
                int count = 0;
                int c;
                while((c = buffer.read()) != -1) {
                    b[off++] = (byte)c;
                    ++count;
                    if(c == '\n' || count == len) {
                        break;
                    }
                }
                return count > 0?count:-1;
            }
        }

        @Override
        public int read() throws IOException {
            return buffer.read();
        }

        @Override
        public int read(byte[] b) throws IOException {
            return buffer.read(b);
        }

        @Override
        public boolean isFinished() {
            return buffer.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener arg0) {
            throw new RuntimeException("Not implemented");
        }

    }

}