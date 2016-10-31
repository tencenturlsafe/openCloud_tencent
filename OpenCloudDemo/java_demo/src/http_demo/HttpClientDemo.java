package http_demo;

import java.io.IOException;
import java.util.Date;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;

import udp_demo.UdpClientDemo;

import com.qq.weixin.mp.aes.AesException;
import com.qq.weixin.mp.aes.WXBizMsgCrypt;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

public class HttpClientDemo {

	@SuppressWarnings("deprecation")
	public static void main(String[] args) throws AesException, HttpException, IOException {

		if (args.length < 2) {
			System.out.println("Usage: bin appid key");
			return;
		}

		int uiAppId = Integer.parseInt(args[0]);
		String strAppdKey = args[1];

		WXBizMsgCrypt pc = new WXBizMsgCrypt(strAppdKey);

		JSONObject httpProto = new JSONObject();

		JSONObject header = new JSONObject();
		header.element("appid", uiAppId);

		long currentTime = new Date().getTime() / 1000;
		header.element("timestamp", currentTime);

		String sign = UdpClientDemo.MD5(String.valueOf(currentTime) + strAppdKey);
		sign = sign.toLowerCase().substring(16, 32);
		header.element("sign", sign);
		header.element("echostr", "1234567890123456");
		header.element("v", "1.0");

		httpProto.element("header", header);

		JSONArray postUrls = new JSONArray();

		JSONObject reqinfo = new JSONObject();
		reqinfo.element("id", 0);
		reqinfo.element("url", "http://shuaqqbi.com");

		postUrls.add(reqinfo);

		String mingwen = postUrls.toString();

		System.out.println("明文：" + mingwen);

		String miwen = pc.encrypt(mingwen.getBytes());
		httpProto.element("reqinfo", miwen);

		System.out.println("密文：" + miwen);

		HttpClient httpclient = new HttpClient();
		httpclient.getHostConfiguration().setHost("cloud.urlsec.qq.com", 80, "http");

		StringRequestEntity requestEntity = new StringRequestEntity(httpProto.toString(), "application/json", "UTF-8");

		PostMethod method = new PostMethod();
		method.setRequestEntity(requestEntity);

		System.out.println(httpProto.toString()); // 打印结果页面

		try {
			httpclient.executeMethod(method);
		} catch (Exception e) {
			System.out.println(e.toString());
		}

		String response = new String(method.getResponseBodyAsString().getBytes("utf-8"));

		JSONObject rspJson = JSONObject.fromObject(response);
		JSONArray attrJsonArray = rspJson.getJSONArray("url_attr");

		for (int i = 0; i < attrJsonArray.size(); i++) {

			JSONObject attrJson = (JSONObject) attrJsonArray.get(i);
			// 打印返回的信息
			System.out.println("查询的url:" + attrJson.getString("url"));
			System.out.println("查询的url的类型:" + attrJson.getInt("urltype"));
			System.out.println("查询的url的恶意类型:" + attrJson.getInt("eviltype"));
		}

		method.releaseConnection();
	}

}
