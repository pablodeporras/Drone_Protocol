/*
Autores: Pablo de Porras Carrique
 */
package practica2dar;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Scanner;

// Para implementar conexión segura SSL
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;

// Para implementar el cifrado simétrico 
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;





public class Cliente {
    
    private static final String ALGORITHM = "AES";
    private static final String KEY = "DAR";
    
    
    // Metodos para encriptar y desencriptar los datos en AES con la contraseña DAR
        public static byte[] encrypt(String data) throws Exception {
        Key key = generateKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] encryptedData) throws Exception {
        Key key = generateKey();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }

    private static Key generateKey() throws Exception {
        return new SecretKeySpec(KEY.getBytes(), ALGORITHM);
    }
    
    
    
    
    
    
    
    // Método que crea el hash MD5
    public static String md5(String clear) throws Exception {
        
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] b = md.digest(clear.getBytes());
        int size = b.length;
        StringBuffer h = new StringBuffer(size);
        
    //algoritmo y arreglo md5
    
        for (int i = 0; i < size; i++) {
            int u = b[i] & 255;
                if (u < 16) {
                    h.append("0" + Integer.toHexString(u));
                }
               else {
                    h.append(Integer.toHexString(u));
               }
           }
      //Hash de salida
      return h.toString();
    }

 
    
    public static void main(String[] args) throws Exception{
        final int puerto=9999;
        final String host="localhost";
        Scanner entrada = new Scanner(System.in);

            try {
                boolean terminar=false;
                Socket socket = new  Socket(host, puerto);
                
                while(!terminar){
                    InputStreamReader inputstream = new InputStreamReader(socket.getInputStream());
                    BufferedReader in = new BufferedReader(inputstream);
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
              
                    String mensaje = entrada.nextLine();
                    
                    if (mensaje.compareTo("log:admin:finisterre") == 0){
                        String[] vector = mensaje.split(":"); // Un string con vector para guardar usuario y contraseña 
                        String user = vector[1];
                        String pass = vector[2]; 
                        String hashPass = md5(pass);  // Realizamos el hash a la contraseña 
                        String entradaOriginal = hashPass; 
                        String cadenaCodificada = Base64.getEncoder().encodeToString(entradaOriginal.getBytes()); // Codificamos el hash de la contraseña en base64
                        String h = "log:" + user + ":" + cadenaCodificada; // log:admin:(hash codificado en base64)
                        System.out.println(h);
                        out.println(h);
                        out.flush();
                    }
                    else {
                        
                        //mensaje = encrypt(mensaje);
                        out.println(mensaje);
                        out.flush();
                    }
                    
                    String respuesta = in.readLine();
                    System.out.println(respuesta);
                    
                    if (respuesta.compareTo("CerrarSesion OK")==0){
                        terminar=true;
                        socket.close();
                    }
                }
            } catch (IOException ex) {
                Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
            }
            
             
    }       
}