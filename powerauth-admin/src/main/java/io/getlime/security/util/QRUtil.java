package io.getlime.security.util;

import com.google.common.io.BaseEncoding;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Utility class for generating QR codes.
 *
 * @author Petr Dvorak
 */
public class QRUtil {

    /**
     * Encode the string data into a QR code of a given size (size = width = height)
     * and return the result as "data:" URL.
     *
     * @param qrCodeData String with the data to be stored in the QR code.
     * @param qrCodeSize Size of the QR code in pixels.
     * @return Data URL with encoded QR code.
     */
    public static String encode(String qrCodeData, int qrCodeSize) {
        try {
            BitMatrix matrix = new MultiFormatWriter().encode(
                    new String(qrCodeData.getBytes("UTF-8"), "ISO-8859-1"),
                    BarcodeFormat.QR_CODE,
                    qrCodeSize,
                    qrCodeSize);
            BufferedImage image = MatrixToImageWriter.toBufferedImage(matrix);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(image, "jpg", baos);
            byte[] bytes = baos.toByteArray();
            return "data:image/png;base64," + BaseEncoding.base64().encode(bytes);
        } catch (WriterException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
