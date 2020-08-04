package edu.buffalo.cse.cse486586.simpledht;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider {

    static final int SERVER_PORT = 10000;
    static final String REMOTE_PORT0 = "11108";
    static final String REMOTE_PORT1 = "11112";
    static final String REMOTE_PORT2 = "11116";
    static final String REMOTE_PORT3 = "11120";
    static final String REMOTE_PORT4 = "11124";
    static final String PROVIDER_URI = "edu.buffalo.cse.cse486586.simpledht.provider";
    public String predecessor = null;
    public String predecessor_id = null;
    public String successor_id = null;
    public String successor = null;
    public String id = null;
    public String self_port = null;

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        Log.v("successor is"," from outside "+ successor);
        Log.v(" predecessor is"," from outside"+predecessor);
        Log.v(" my port yuss", self_port);
        if((selection.equals("*")&&(successor == null && predecessor == null))||selection.equals("@")) {
            File[] files = getContext().getFilesDir().listFiles();
            for (File file : files) {
                file.delete();
//                Log.v("query check is", " checking result cursor log "+resultCursor.getCount());
            }
        }
        else if(selection.equals("*")){
            File[] files = getContext().getFilesDir().listFiles();
            for (File file : files) {
                file.delete();
//                Log.v("query check is", " checking result cursor log "+resultCursor.getCount());
            }
            try {
                List<QueryObject> queryObjects = new ClientTask1().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,
                        "delete*",selection,"").get();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }

            return 0;
        }
        String key = null;
        try {
            key = genHash(selection);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
//        file[0].getName();
//        file[0].get
//        new File(file[0].getPath())
        Log.v("query", " key is "+selection);
        String msg = "";
        if((successor==null && predecessor == null)||
                (key.compareTo(id)<=0&&key.compareTo(predecessor_id)>0)||
                (key.compareTo(id)<=0&&id.compareTo(predecessor_id)<0)||
                (key.compareTo(id)>0&&id.compareTo(predecessor_id)<0&&key.compareTo(predecessor_id)>0)
        ) {
            File file = new File(getContext().getFilesDir(),selection);
            file.delete();
        }
        else{
            try {
                List<QueryObject> queryObjects = new ClientTask1().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "delete",selection,"").get();
//                queryObject = queryObjects.get(0);
//                resultCursor.newRow().add("key", queryObject.getKey()).add("value", queryObject.getValue().trim());
//                Log.v("query ka", "value ai "+ resultCursor.getString(0)+" aur key thi"+selection);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub


        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub

        String key = (String) values.get("key");
        String key1 =key;
        String val = values.get("value") + "\n";
        Log.v("Insert", " I came in this port "+self_port+ " with Key "+key1+" and its hash "
                +key);
        try {
            key = genHash(key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if((successor==null && predecessor == null)||
                (key.compareTo(id)<=0&&key.compareTo(predecessor_id)>0)||
                (key.compareTo(id)<=0&&id.compareTo(predecessor_id)<0)||
                (key.compareTo(id)>0&&id.compareTo(predecessor_id)<0&&key.compareTo(predecessor_id)>0)
        ){
            Log.v("Insert"," insert the key "+key1+" whose hash is "+key+ " on port "+ self_port);
            FileOutputStream outputStream;

            try {
                outputStream = getContext().openFileOutput(key1, getContext().MODE_PRIVATE);
                outputStream.write(val.getBytes());
                outputStream.close();
            } catch (Exception e) {
                Log.v("insert", "File write failed");
            }
            Log.v("insert", values.toString());
        }
        else{
            try {
                Log.v("Insert"," Passing the insert to successor "+successor+ " for key "+
                        key1 + " with hash "+ key);
                List<QueryObject> queryObject = new ClientTask1().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, key1,val,"insert").get();
//                Log.v("result check", " insert ka log "+work);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }

        return uri;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        TelephonyManager tel = (TelephonyManager) this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        final String myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        final String hash1 = String.valueOf((Integer.parseInt(portStr) ));
        try {
            id = genHash(hash1);
            Log.v("hash is", " my emulator is "+hash1+ " with id ie hash "+id);
            self_port = myPort;
            Log.v("test", " my port is "+ self_port+ " my hash id is "+ id);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e("test", "Can't create a ServerSocket");
            Log.v("error", "testing "+e.getMessage());
            return false;
        }

        if(!myPort.equals(REMOTE_PORT0)){
            try {
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, myPort).get();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
        Log.v("test","My port is "+self_port);
        Log.v("test"," My predecessor is "+ predecessor);
        Log.v("test"," My successor is "+ successor);
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {
        // TODO Auto-generated method stub
        String key = selection;
        Log.v("query"," key is "+key);
        QueryObject queryObject = null;
        MatrixCursor resultCursor = new MatrixCursor(new String[]{"key", "value"});
        if((selection.equals("*")&&(successor == null && predecessor == null))||selection.equals("@")) {
            File[] files = getContext().getFilesDir().listFiles();
            for (File file : files) {
                resultCursor = getResults(file.getName(), resultCursor, selection);
//                Log.v("query check is", " checking result cursor log "+resultCursor.getCount());
            }
            return resultCursor;
        }
        else if (selection.equals("*")){
            File[] files = getContext().getFilesDir().listFiles();
            for (File file : files) {
                resultCursor = getResults(file.getName(), resultCursor, selection);
//                Log.v("query check is", " checking result cursor log "+resultCursor.getCount());
            }
            try {
                List<QueryObject> queryObjects = new ClientTask1().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR,
                        "query*",selection,"").get();
                for(QueryObject queryObject1: queryObjects){
                    resultCursor.newRow().add("key", queryObject1.getKey()).add("value",
                            queryObject1.getValue().trim());
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
            return resultCursor;

        }
        try {
            key = genHash(selection);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
//        file[0].getName();
//        file[0].get
//        new File(file[0].getPath())
        Log.v("query", " key is "+selection);
        String msg = "";
        if((successor==null && predecessor == null)||
                (key.compareTo(id)<=0&&key.compareTo(predecessor_id)>0)||
                (key.compareTo(id)<=0&&id.compareTo(predecessor_id)<0)||
                (key.compareTo(id)>0&&id.compareTo(predecessor_id)<0&&key.compareTo(predecessor_id)>0)
        ) {
            resultCursor = getResults(selection, resultCursor, selection);
        }
        else{
            try {
                List<QueryObject> queryObjects = new ClientTask1().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query",selection,"").get();
                queryObject = queryObjects.get(0);
                resultCursor.newRow().add("key", queryObject.getKey()).add("value", queryObject.getValue().trim());
//                Log.v("query ka", "value ai "+ resultCursor.getString(0)+" aur key thi"+selection);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
        return resultCursor;
    }
    public List<QueryObject> getAllFiles(){
        List<QueryObject> queryObjects = new ArrayList<QueryObject>();
        File[] files = getContext().getFilesDir().listFiles();
        for (File file : files) {
//                Log.v("query check is", " checking result cursor log "+resultCursor.getCount());
            String value = queryHelper(file.getName(),"");
            QueryObject queryObject = new QueryObject(file.getName(),value);
            queryObjects.add(queryObject);
        }
        return queryObjects;
    }
    public QueryObject queryChecker(String selection)  {
        try {
            String key = genHash(selection);
            String value = "";
            QueryObject queryObject = null;
            if((successor==null && predecessor == null)||
                    (key.compareTo(id)<=0&&key.compareTo(predecessor_id)>0)||
                    (key.compareTo(id)<=0&&id.compareTo(predecessor_id)<0)||
                    (key.compareTo(id)>0&&id.compareTo(predecessor_id)<0&&key.compareTo(predecessor_id)>0)
            ){
                value = queryHelper(selection,value);
                queryObject = new QueryObject(selection,value);
            }
            else{
                List<QueryObject> q = new ClientTask1().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "query",selection,"").get();
                queryObject = q.get(0);
            }
            Log.v(" query object", queryObject.getKey()+"  "+ queryObject.getValue());
            return queryObject;
        }
        catch (NoSuchAlgorithmException ex){
            ex.getStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }


    public MatrixCursor getResults(String key,MatrixCursor resultCursor,String selection)  {
        Log.v("getResults","key is "+key);
        String msg = "";
        msg = queryHelper(key,msg);
        Log.v("query", "yahan toh chal " + key);
        resultCursor.newRow().add("key", key).add("value", msg.trim());
        return resultCursor;
    }
    public String queryHelper(String key,String msg)  {
        try{
            InputStream inputStream = getContext().openFileInput(key);
            InputStreamReader InputRead = new InputStreamReader(inputStream);

            char[] buffer = new char[100];

            int c;

            while ((c = InputRead.read(buffer)) > 0) {
                // char to string conversion
                String readstring = String.copyValueOf(buffer, 0, c);
                msg += readstring;
            }
            Log.v("query", "message is key " + key + " value is " + msg);
            InputRead.close();
            return msg;
        } catch (FileNotFoundException e) {
            Log.v("phata", "yahan phata 1");
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
            Log.v("phata", "yahan phata 1");
        } catch (Exception ex) {
            Log.v("query", ex.getMessage());
            Log.v("phata", "yahan phata 1");
            return null;
        }
        return null;
}

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private class ClientTask extends AsyncTask<String, Void, Void>{
        @Override
        protected Void doInBackground(String... msgs){
            Socket socket = null;
            try {
                String myPort = msgs[0];
                socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(REMOTE_PORT0));
                socket.setSoTimeout(50000);
                String msgToSend = "lookUpJoin"+"|"+id+"|"+self_port;
                Log.v("test"," sending message "+msgToSend);
                DataOutputStream message0 = new DataOutputStream(socket.getOutputStream());
                message0.writeUTF(msgToSend);
                DataInputStream messageReceived = new DataInputStream(socket.getInputStream());
                String m = messageReceived.readUTF();
                Log.v("test"," message received is "+m);
                String[] messageArray = m.split(Pattern.quote("|"));
                Log.v("split client"," message array length is "+messageArray.length+" and went till"+"4");
                predecessor_id = messageArray[0];
                predecessor = messageArray[1];
                successor_id = messageArray[2];
                successor = messageArray[3];
                Log.v(" successor is ",successor);
                Log.v(" predecessor is ",predecessor);
                Log.v("answer", "my port is "+ self_port+" my successor is "+
                        successor+ " my predecessor is"+ predecessor);
                Socket socket1 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(predecessor));
                DataOutputStream message1 = new DataOutputStream(socket1.getOutputStream());
                String messageForPredecessor = "successor"+"|"+myPort+"|"+id;
                message1.writeUTF(messageForPredecessor);// message sent to predecessor
                Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(successor));
                DataOutputStream message2 = new DataOutputStream(socket2.getOutputStream());
                String messageForSuccesor = "predecessor"+"|"+myPort+"|"+id;
                message2.writeUTF(messageForSuccesor);
                socket.close();
                socket1.close();
            } catch (SocketTimeoutException e){
                Log.v(" socketTi phata"," Socket Timeout main phata");

            }catch (UnknownHostException e ){
                Log.v(" Unknowhost phata"," unknown main phata");
            }
            catch (IOException e) {
                e.printStackTrace();
                Log.v(" socketTi phata"," IO main phata");

            }
            return null;
        }
    }

    private class ClientTask1 extends AsyncTask<String, Void, List<QueryObject>>{
        @Override
        protected List<QueryObject> doInBackground(String... msgs){
//            if(msgs[3].equals("insert")){
                try {
                    if(msgs[2].equals("insert")) {
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(successor));
                        DataOutputStream message1 = new DataOutputStream(socket.getOutputStream());
                        String messageToSend = "insert" + "|" + msgs[0]+"|"+msgs[1];
                        message1.writeUTF(messageToSend);
                        return null;
                    }
                    else if(msgs[0].equals("query")){
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(successor));
                        DataOutputStream message1 = new DataOutputStream(socket.getOutputStream());
                        String messageToSend = "query" + "|" + msgs[1];
                        Log.v("query"," message to send is "+ messageToSend);
                        message1.writeUTF(messageToSend);
//                        ObjectInputStream messageReceived = new ObjectInputStream((socket.getInputStream()));
                        ObjectInputStream messageReceived = new ObjectInputStream(socket.getInputStream());
                        QueryObject queryObject = (QueryObject) messageReceived.readObject();
                        List<QueryObject> queryObjects = new ArrayList<QueryObject>();
                        queryObjects.add(queryObject);
//                        String messageQuery = messageReceived.readUTF();
//                        String[] messageArray = messageQuery.split(Pattern.quote("|"));
//                        MatrixCursor resultCursor = new MatrixCursor(new String[]{"key", "value"});
//                        resultCursor.newRow().add("key", messageArray[0]).add("value", messageArray[1].trim());
//                        MatrixCursor matrixCursor = (MatrixCursor) messageReceived.readObject();
//                        Log.v("query server"," object value received is "+matrixCursor.getString(0));
                        return queryObjects;
                    }
                    else if(msgs[0].equals("query*")){
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(successor));
                        DataOutputStream message1 = new DataOutputStream(socket.getOutputStream());
                        String messageToSend = "query*" + "|" + self_port;
                        message1.writeUTF(messageToSend);
                        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
                        List<QueryObject> queryObjects = (List<QueryObject>)objectInputStream.readObject();
                        return queryObjects;
                    }
                    else if(msgs[0].equals("delete*")){
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(successor));
                        DataOutputStream message1 = new DataOutputStream(socket.getOutputStream());
                        String messageToSend = "delete*" + "|" + self_port;
                        message1.writeUTF(messageToSend);
                    }
                    else if(msgs[0].equals("delete")){
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(successor));
                        DataOutputStream message1 = new DataOutputStream(socket.getOutputStream());
                        String messageToSend = "delete" + "|" + msgs[1];
                        Log.v("query"," message to send is "+ messageToSend);
                        message1.writeUTF(messageToSend);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
//            }
            return null;
        }
    }



    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {
        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            while (true) {
                ServerSocket serverSocket = sockets[0];
                Socket socket = null;
                Integer portClient = -1;
                try {
                    socket = serverSocket.accept();
//                    ObjectInputStream
//                    ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                    DataInputStream messageReceived = new DataInputStream(socket.getInputStream());
                    String message = messageReceived.readUTF();
                    Log.v("info of server", message + "zzzzz");
                    String[] messageArray = message.split(Pattern.quote("|"));
                    Log.v("split"," message array length is "+messageArray.length+" and went till"+"3");

//                    portClient = Integer.parseInt(messageArray[1]);
//                    if("join".equals(messageArray[0])){
//                        String msgToSend = null;
//                        if(predecessor==null&& successor ==null){
//                            msgToSend = "answer"+"|"+REMOTE_PORT0+"|"+REMOTE_PORT0;
//                            predecessor = messageArray[1];
//                            successor = messageArray[1];
//                        }
//                        else{
//                            msgToSend = "answer"+"|"+predecessor+"|"+REMOTE_PORT0;
//                            predecessor = messageArray[1];
//                        }
//                        DataOutputStream message0 = new DataOutputStream(socket.getOutputStream());
//                        message0.writeUTF(msgToSend);
//                    }
//                    else if("successor".equals(messageArray[0])){
//                        successor = messageArray[1];
//                    }
                    Log.v("message is",messageArray[0]);
                    if("lookUpJoin".equals(messageArray[0])){
                        Log.v("test","i am inside");
                        String sent_Id = messageArray[1];
                        String lookUpResponse = null;
                        if(predecessor == null && successor ==null){
                            lookUpResponse = id+"|"+REMOTE_PORT0+"|"+id+"|"+REMOTE_PORT0;
                            predecessor_id = sent_Id;
                            successor_id = sent_Id;
                            predecessor = messageArray[2];
                            successor = messageArray[2];
                            Log.v("answer", "my port is "+ self_port+" my successor is "+
                                    successor+ " my predecessor is"+ predecessor);
                        }
                        else{
                            Log.v("join issue"," id is "+id+" and joining id is "+sent_Id);
                            if(id.compareTo(sent_Id)>=0&&sent_Id.compareTo(predecessor_id)>0){
                                lookUpResponse = predecessor_id+"|"+predecessor+"|"+id+"|"+self_port;
                                predecessor_id = sent_Id;
                                predecessor = messageArray[2];
                                Log.v("answer", "my port is "+ self_port+" my successor is "+
                                        successor+ " my predecessor is"+ predecessor);
                            }
                            else if(sent_Id.compareTo(id)>0){
                                Log.v(" debug", " my id is "+ id+" successor id is "+ successor_id+" and successor is "
                                        + successor);
                                if(id.compareTo(successor_id)>0){
                                    Log.v("debug", " yahan milla");
                                    Log.v("debug "," successor id is "+ successor_id+" successor "+ successor);
                                    lookUpResponse = id+"|"+self_port+"|"+successor_id+"|"+successor;
                                    successor = messageArray[2];
                                    successor_id = sent_Id;
                                }
                                else{
                                    lookUpResponse = sendToSuccessor(sent_Id,messageArray);
//                                    Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
//                                            Integer.parseInt(successor));
//                                    DataOutputStream message_join = new DataOutputStream(socket2.getOutputStream());
//                                    String message_cascade = "lookUpJoin"+"|"+sent_Id+"|"+messageArray[2];
//                                    message_join.writeUTF(message_cascade);
//                                    DataInputStream message_join_read = new DataInputStream(socket2.getInputStream());
//                                    String message_join_cascade = message_join_read.readUTF();
//                                    String[] messageArray_join = message_join_cascade.split(Pattern.quote("|"));
//                                    lookUpResponse = messageArray_join[0]+"|"+messageArray_join[1]+"|"+
//                                            messageArray_join[2]+"|"+messageArray_join[3];
                                }

                            }
                            else if(id.compareTo(sent_Id)>0){
                                if(id.compareTo(successor_id)<0&&id.compareTo(predecessor_id)<0){
                                    lookUpResponse = predecessor_id+"|"+predecessor+"|"+id+"|"+self_port;
                                    predecessor_id = sent_Id;
                                    predecessor = messageArray[2];
                                    Log.v("answer", " my port is "+ self_port+" my successor is "+
                                            successor+ " my predecessor is"+ predecessor);
                                }
                                else{
                                    lookUpResponse = sendToSuccessor(sent_Id,messageArray);
                                }
                            }
                        }
                        DataOutputStream messageToSendForJoin = new DataOutputStream(socket.getOutputStream());
                        messageToSendForJoin.writeUTF(lookUpResponse);
                    }
                    else if("successor".equals(messageArray[0])){
                        successor = messageArray[1];
                        successor_id = messageArray[2];
                        Log.v("answer successor", "my port is "+ self_port+" my successor is "+
                                successor+ " my predecessor is"+ predecessor);
                    }
                    else if("predecessor".equals(messageArray[0])){
                        predecessor = messageArray[1];
                        predecessor_id = messageArray[2];
                        Log.v("answer predecessor", "my port is "+ self_port+" my successor is "+
                                successor+ " my predecessor is"+ predecessor);
                    }
                    else if("insert".equals(messageArray[0])){
                        Log.v(" test"," insert value checking");
                        ContentValues keyValueToInsert = new ContentValues();
                        String key = messageArray[1];
                        keyValueToInsert.put("key",key);
                        keyValueToInsert.put("value",  messageArray[2]);
                        Uri.Builder uriBuilder = new Uri.Builder();
                        uriBuilder.authority(PROVIDER_URI);
                        uriBuilder.scheme("content");
                        Uri uri = uriBuilder.build();
                        Uri newUri = insert(uri, keyValueToInsert);
                    }
                    else if("query".equals(messageArray[0])){
//                        MatrixCursor cursor = (MatrixCursor) query(null, null, messageArray[1],null,null);
                        QueryObject queryObject = queryChecker(messageArray[1]);
                        Log.v(" query Object is",queryObject.getKey()+" val "+queryObject.getValue());
                        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                        objectOutputStream.writeObject(queryObject);
                    }
                    else if("query*".equals(messageArray[0])){
//                        MatrixCursor cursor = (MatrixCursor) query(null, null, messageArray[1],null,null);
                        List<QueryObject> queryObjects = getAllFiles();
                        if(!messageArray[1].equals(successor)){
                            Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    Integer.parseInt(successor));
                            DataOutputStream message_all = new DataOutputStream(socket2.getOutputStream());
                            String messageToSendForAll = "query*"+"|"+messageArray[1];
                            message_all.writeUTF(messageToSendForAll);
                            ObjectInputStream objectInputStream = new ObjectInputStream(socket2.getInputStream());
                            List<QueryObject> queryObjects1 = (List<QueryObject>) objectInputStream.readObject();
                            queryObjects.addAll(queryObjects1);
//                            for(QueryObject queryObject:queryObjects1){
//                                queryObjects.add(queryObject);
//                            }
                        }
                        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                        objectOutputStream.writeObject(queryObjects);
                    }
                    else if("delete*".equals(messageArray[0])){
                        File[] files = getContext().getFilesDir().listFiles();
                        for (File file : files) {
                            file.delete();
//                Log.v("query check is", " checking result cursor log "+resultCursor.getCount());
                        }
                        if(!messageArray[1].equals(successor)){
                            Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    Integer.parseInt(successor));
                            DataOutputStream message_all = new DataOutputStream(socket2.getOutputStream());
                            String messageToSendForAll = "delete*"+"|"+messageArray[1];
                            message_all.writeUTF(messageToSendForAll);
                        }
                    }
                    else if("delete".equals(messageArray[0])){
                        delete(null,messageArray[1],null);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }

            }
        }
    }

    public String sendToSuccessor(String sent_Id,String [] messageArray) throws IOException {
        Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                Integer.parseInt(successor));
        DataOutputStream message_join = new DataOutputStream(socket2.getOutputStream());
        String message_cascade = "lookUpJoin"+"|"+sent_Id+"|"+messageArray[2];
        message_join.writeUTF(message_cascade);
        DataInputStream message_join_read = new DataInputStream(socket2.getInputStream());
        String message_join_cascade = message_join_read.readUTF();
        String[] messageArray_join = message_join_cascade.split(Pattern.quote("|"));
        Log.v("split succesor"," message array join cascase length is "+messageArray_join.length + " and went till"+"4");
        String lookUpResponse = messageArray_join[0]+"|"+messageArray_join[1]+"|"+
                messageArray_join[2]+"|"+messageArray_join[3];
        return lookUpResponse;
    }

}
