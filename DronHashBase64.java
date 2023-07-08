/*
Autores: Pablo de Porras Carrique
 */
package practica2dar;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Base64;

// Para implementar conexión segura SSL
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

// Para implementar el cifrado simétrico 
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key; 



public class DronHashBase64{

    static final int Bloqueado = 1;
    static final int MotoresApagados = 2;
    static final int MotoresEncendidos = 3;
    static final int EsperandoOrdenes = 4;
    static final int RealizandoAccion = 5;
    static final int CerrandoSesion = 6;

                
    private static String usuario = "admin";
    private static String contrasena = "finisterre";
    
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
    
    
    
    
    
    
    
    
    // Este metodo realiza el hash de un string de entrada
    public static String md5(String pass) throws Exception {
        
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] b = md.digest(pass.getBytes());
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
    //Devuelve la clave con el hash aplicado en un string
    return h.toString();
    }

    private DronHashBase64(int puerto) throws Exception{
        
        try{
            // Abrimos un socket de servidor para escuchar en un puerto.
            ServerSocket serverSocket = new ServerSocket(puerto);
            
            // Creamos un servidor iterativo: acepta una conexión, procesa los mensajes, cierra la conexión, y empieza de nuevo:
            boolean salir = false;
            while (!salir) {
                // Esperamos una solicitud de conexión TCP de un cliente:
                Socket socket = serverSocket.accept();

                // Obtenemos un objeto para entrada y otro de salida:
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream());

                // simulamos la máquina de estados. Leemos un mensaje, y miramos qué hacer según el estado actual:
                // Empezamos con el estado inicial:
                int estado = Bloqueado;
                boolean terminar = false;
                String linea = "";
                
                // Variables necesarias para el procesamiento del protocolo:
                boolean eventoConsumirMensaje=true;

                
    // Leemos mensaje, procesamos, volvemos...
            while (!terminar) {

                // Estrictamente, habría que leer de una cola de eventos. Algunos de ellos serían
                // la recepción de un mensaje, o de una llamada de la aplicación.
                // Esta cola, la simulamos aquí, distinguiendo si es un mensaje u otro tipo de 
                // Leemos una línea de texto,
                linea = "";

            if (eventoConsumirMensaje) {
                linea = in.readLine();
            }

            if (linea != null) {

            switch(estado) {
                case Bloqueado:
                
                if(linea.startsWith("log"+":")){
                    
                    String []campos=linea.split(":");
                    if(campos.length==3){
                                    
                        // Almacenamos el secreto, que permita comprobar que no hizo trampas el cliente.
                        String user=campos[1];
                        String pass=campos[2];
                        
                        
                        // cambiamos de estado
                        eventoConsumirMensaje=false; 
                                    
                        String mensaje = "NOK";
                        
                        
                    /*
                    DECODIFICADOR BASE 64
                    */
                    // El cliente envia un hash codificado en base64, debemos decodificarlo y compararlo al hash original
                    byte[] decodedBytes = Base64.getDecoder().decode(pass);
                    String decodedHash = new String(decodedBytes);
                    System.out.println("Hash decodificado: " + decodedHash);
                    System.out.println();
                    
                    
                    /*
                    HASH MD5
                    */
                    String hash1=md5(contrasena); // Creamos un string (hash1) con el valor de entrada contraseña original
                    System.out.println("Hash original: " + hash1); // Este es el hash original que el servidor conoce
                    out.flush();
                    
                    // Como entrada usamos la contraseña decodificada de Base64
//                    String hashPass = md5(decodedPass); // Creamos un string (hash1) con el valor de entrada contraseña PUTTY
//                    System.out.println("Hash introducido: " + hashPass);
                        
                        if (user.equals(usuario) && hash1.equals(decodedHash)) {
                            mensaje = "OK";
                            System.out.println("Autenticacion " + mensaje);;
                            out.println("Autenticacion " + mensaje);
                            out.flush();

                            estado = MotoresApagados; 
                            eventoConsumirMensaje=true;
                            
                        }           
                        else {
                            mensaje = "NOK";
                            System.out.println("Autenticacion " + mensaje);
                            out.println("Autenticacion " + mensaje);
                            out.flush();
                            estado = Bloqueado;
                            eventoConsumirMensaje=true; 
                            
                            }      
                    }
                    else{
                        out.println("Error Sintaxis");
                        out.flush();
                        estado = Bloqueado;
                        eventoConsumirMensaje=true; 
                    }
                }
                
                
                case MotoresApagados:
                    if(linea.startsWith("mot"+":")){
                    // empeiza por "sec:":
                    String []campos=linea.split(":");
                    if(campos.length==2){
                                    
                        // Almacenamos el secreto, que permita comprobar que no hizo trampas el cliente.
                        String enciende=campos[1];
                        //mot:mMotores
                        // cambiamos de estado
                        eventoConsumirMensaje=false; 
                                    
                        String mensaje = "NOK";
                        
                        if (enciende.equals("mMotores")) {
                            mensaje = "OK";
                            System.out.println("Motores " + mensaje);
                            out.println("Motores " + mensaje);
                            out.flush();
                            estado = EsperandoOrdenes; 
                            eventoConsumirMensaje=true;
                            
                        }           
                        else{
                            mensaje = "NOK";
                            System.out.println("Motores " + mensaje);
                            out.println("Motores " + mensaje);
                            out.flush();
                            estado = MotoresApagados;
                            eventoConsumirMensaje=true; 
                            
                            }      
                    }
                    else{
                        out.println("Error Sintaxis");
                        out.flush();
                        estado = MotoresApagados;
                        eventoConsumirMensaje=true; 
                    }
                }
                    
                    case EsperandoOrdenes:
                    if(linea.startsWith("ord"+":")){
                        
                    // empeiza por "sec:":
                    String []campos=linea.split(":");
                    if(campos.length==2){
                                    
                        // Almacenamos el secreto, que permita comprobar que no hizo trampas el cliente.
                        String orden=campos[1];
                        //mot:mMotores
                        // cambiamos de estado
                        eventoConsumirMensaje=false; 
                                    
                        String mensaje = "NOK";
                        
                        if (orden.equals("mAvanzar")) {
                            mensaje = "OK";
                            System.out.println("Avanzar " + mensaje);
                            out.println("Avanzar " + mensaje);
                            out.flush();
                            estado = CerrandoSesion; 
                            eventoConsumirMensaje=true;
                            
                        }           
                        else{
                            mensaje = "NOK";
                            System.out.println("Avanzar " + mensaje);
                            out.println("Avanzar " + mensaje);
                            out.flush();
                            estado = EsperandoOrdenes;
                            eventoConsumirMensaje=true; 
                            
                            }      
                    }
                    else{
                        out.println("Error Sintaxis");
                        out.flush();
                        estado = EsperandoOrdenes;
                        eventoConsumirMensaje=true; 
                    }
                }    
                    
                case CerrandoSesion:
                    if(linea.startsWith("off"+":")){
                    // empeiza por "sec:":
                    String []campos=linea.split(":");
                    if(campos.length==2){
                                    
                        // Almacenamos el secreto, que permita comprobar que no hizo trampas el cliente.
                        String apagar=campos[1];
                        //off:mCerrarSesion
                        
                        // cambiamos de estado
                        eventoConsumirMensaje=false; 
                                    
                        String mensaje = "NOK";
                        
                        if (apagar.equals("mCerrarSesion")) {
                            mensaje = "OK";
                            System.out.println("CerrarSesion " + mensaje);
                            out.println("CerrarSesion " + mensaje);
                            out.flush();
                            estado = Bloqueado; 
                            eventoConsumirMensaje=true;
                            terminar = true;    
                        }           
                        else{
                            mensaje = "NOK";
                            System.out.println("CerrarSesion " + mensaje);
                            out.println("CerrarSesion " + mensaje);
                            out.flush();
                            estado = CerrandoSesion;
                            eventoConsumirMensaje=true; 
                            
                            }  

                    }
                    else{
                        out.println("Error Sintaxis");
                        out.flush();
                        estado = MotoresApagados;
                        eventoConsumirMensaje=true; 
                    }
            
                    }
            
            }
            }
            }
            }
        }
        catch (IOException ex) {
            System.out.println("Servidor: error al escuchar en puerto "+puerto);
        }
            }    
    
    
    // Para convertir datos a un hash necesitamos realizar los siguientes pasos: 
    /* 
    1. Importat la clase MessageDigest.
    2. Convertir datos en flujo de bytes. 
    3. Usar el método getInstance() para crear instancia del MD5.
    4. Usar le método digest pasando los datos de los que queremos obtener el hash.
    5. Almacenar datos en un array de bytes.
    6. Convertir el flujo de bytes a cadena. 
    */
    
//    public static void md5(String contrasena) throws Exception {
//        
//
//        MessageDigest md = MessageDigest.getInstance("MD5");
//        byte[] b = md.digest(contrasena.getBytes());
//        String hash = Arrays.toString(b);
//        System.out.println("Hash MD5: " + hash);
//
//    }
//    
//    // Clase que permite decodificar una contraseña que viene dada en Base64
//    public static String Base64(String contrasena){
//        byte[] decodedBytes = Base64.getDecoder().decode(contrasena);
//        String decodedPass = new String(decodedBytes);
//        out.println("Contrasena decodificada: " + decodedPass);
//        out.flush();
//        
//        return decodedPass; 
//    }
//    
    public static void main(String args[]) throws Exception{
        new DronHashBase64(9999);
        
    }
    
}