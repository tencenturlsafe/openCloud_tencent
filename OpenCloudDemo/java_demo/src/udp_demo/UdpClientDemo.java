package udp_demo;

import java.io.StringReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import udp_demo.Req.ReqPkg;
import udp_demo.Req.ReqPkg.Builder;

import com.google.protobuf.ByteString;
import com.qq.weixin.mp.aes.WXBizMsgCrypt;

public class UdpClientDemo {

	 public final static String MD5(String s) {
	        char hexDigits[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	        try {
	            byte[] btInput = s.getBytes();
	            // 获得MD5摘要算法的 MessageDigest 对象
	            MessageDigest mdInst = MessageDigest.getInstance("MD5");
	            // 使用指定的字节更新摘要
	            mdInst.update(btInput);
	            // 获得密文
	            byte[] md = mdInst.digest();
	            // 把密文转换成十六进制的字符串形式
	            int j = md.length;
	            char str[] = new char[j * 2];
	            int k = 0;
	            for (int i = 0; i < j; i++) {
	                byte byte0 = md[i];
	                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
	                str[k++] = hexDigits[byte0 & 0xf];
	            }
	            return new String(str);
	        } catch (Exception e) {
	            e.printStackTrace();
	            return null;
	        }
	    }

	public static void main(String[] args) throws Exception {
        if(args.length<2)
        {
            System.out.println("Usage: bin appid key");
            return;
        }

        int uiAppId = Integer.parseInt(args[0]);
        String strAppdKey = args[1];

		WXBizMsgCrypt pc = new WXBizMsgCrypt(strAppdKey);

		Req.ReqPkg.Builder reqPkg = Req.ReqPkg.newBuilder();
		Req.ReqPkg.Header.Builder header = Req.ReqPkg.Header.newBuilder();

		header.setAppid(uiAppId);
		header.setEchostr(ByteString.copyFromUtf8("1111"));
		header.setIp(1234);

		long currentTime=new Date().getTime();
		header.setTime(currentTime/1000);


		String sign = UdpClientDemo.MD5(String.valueOf(currentTime/1000)+strAppdKey);


		sign = sign.toLowerCase().substring(16, 32);


		header.setSign(ByteString.copyFromUtf8(sign));

		header.setV(ByteString.copyFromUtf8("1.0"));

		Req.ReqPkg.ReqInfo.Builder reqInfo = Req.ReqPkg.ReqInfo.newBuilder();
		reqInfo.setDeviceid(ByteString.copyFromUtf8("1"));
		reqInfo.setId(1);
		reqInfo.setUrl(ByteString.copyFromUtf8("http://baidu.com"));


		byte[] s = reqInfo.build().toByteArray();

		// 加密处理
		String miwen = pc.encrypt(s);

		reqPkg.setHeader(header);
		reqPkg.setReqinfo(ByteString.copyFromUtf8(miwen));

		DatagramSocket client = new DatagramSocket();

		InetAddress addr = InetAddress.getByName("cloud.urlsec.qq.com");

		System.out.println("server ip:"+addr.toString());

        int port = 15113;
        DatagramPacket sendPacket
            = new DatagramPacket(reqPkg.build().toByteArray() ,reqPkg.build().toByteArray().length , addr , port);
        client.send(sendPacket);


        System.out.println("发送长度:" + reqPkg.build().toByteArray().length);

        byte[] recvBuf = new byte[100];
        DatagramPacket recvPacket
            = new DatagramPacket(recvBuf , recvBuf.length);
        client.receive(recvPacket);

        Rsp.RspPkg rsp = Rsp.RspPkg.parseFrom(Arrays.copyOf(recvPacket.getData(), recvPacket.getLength()));

        //String recvStr = new String( , 0 ,);
        System.out.println("收到查询返回包:");
        System.out.println("查询的url:" + rsp.getInfos().getUrl().toStringUtf8());
        System.out.println("查询的url的类型:" + rsp.getInfos().getUrltype());
        System.out.println("查询的url的恶意类型:" + rsp.getInfos().getEviltype());

        client.close();
	}
}
