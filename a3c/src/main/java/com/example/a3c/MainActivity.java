package com.example.a3c;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.example.a3c.App_choice.ChooseActivity;
import com.example.a3c.function.otherUtil;
import com.example.a3c.PCAPfile_read.FileRead;
import com.example.a3c.Vpn_service.a3cvpn;

import java.util.Timer;
import java.util.TimerTask;

public class MainActivity extends AppCompatActivity {
    // public String server_address = "170.106.52.13";  // 腾讯云海外服务器

    // public String server_address = "211.65.197.93"; // 默认服务器地址（校内）
    // public String server_address = "10.201.228.119";  // 局域网台式机

//    public String server_address = "124.220.204.64";  // 腾讯云国内服务器
//    public String server_port = "8000";  // 默认服务器端口
//    public String secret = "ELbZ22nCYbkqJftt";// 默认密钥

    public static Button button1;
    public int time_delay = 3000;  // 延时时间（毫秒）

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);  //显示布局
        // 动态获取文件写权限
        otherUtil.RequestPermissions(MainActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE);

        // 创建VPN service为intent，调用a3cvpn.java
        Intent intent = VpnService.prepare(MainActivity.this);

//        //选择APP 按钮
//        Button button0 = findViewById(R.id.choose);
//        button0.setOnClickListener(v -> {
//            //唤起选择页面
//            Intent intentchoose = new Intent(MainActivity.this, ChooseActivity.class);
//            startActivity(intentchoose);
//        });
//
//        //清空APP 按钮
//        Button button_clear = findViewById(R.id.clear);
//        button_clear.setOnClickListener(v -> {
//            //获取SharedPreferences实例 (实例名称，访问权限） *MODE_PRIVATE 表示只有当前应用可以访问这个SharedPreferences实例，其他应用无法访问
//            SharedPreferences sp = getSharedPreferences(a3cvpn.SP_TAG, Context.MODE_PRIVATE);
//            SharedPreferences sp2 = getSharedPreferences(a3cvpn.SP2_TAG, Context.MODE_PRIVATE);
//            if(sp != null) {  //清空sp
//                sp.edit().clear().apply();
//                Log.d("APP-Choose", "APP选择-包名已清空");
//                Toast.makeText(MainActivity.this, "已成功清空APP选择", Toast.LENGTH_SHORT).show();
//            }
//            if(sp2 != null) {  //清空sp2
//                sp2.edit().clear().apply();
//                Log.d("APP-Choose", "APP选择-应用名已清空");
//            }
//        });

        //开始连接 按钮
        button1 = findViewById(R.id.start);
        button1.setOnClickListener(v -> {
            // 检查网络存在
            if (!otherUtil.checkConnectNetwork(MainActivity.this))
            {
                Toast.makeText(MainActivity.this, "警告！当前检测不到网络！", Toast.LENGTH_SHORT).show();
                Log.e("NET-STATE","当前检测不到网络");
                return;
            }
            // 检查VPN service不存在
            if (otherUtil.isVpnUsed())
            {
                Toast.makeText(MainActivity.this, "警告！当前已存在VPN service！", Toast.LENGTH_SHORT).show();
                Log.e("NET-VPN","当前已存在VPN service");
                return;
            }
            // 启动VPN service
            if (intent != null) {
                startActivityForResult(intent, 0);
            } else {
                onActivityResult(0, RESULT_OK, null);
            }

            // 延时检测连接是否超时
            // Handle刷新UI
            Handler handler2 = new Handler(Looper.getMainLooper()) {
                @Override
                public void handleMessage(Message msg) {  // 处理消息
                    switch (msg.what) {
                        case 0:
                            Toast.makeText(MainActivity.this, "连接建立超时！", Toast.LENGTH_SHORT).show();
                            break;
                        case 1:
                            Toast.makeText(MainActivity.this, "连接成功！", Toast.LENGTH_SHORT).show();
                            break;
                    }
                }
            };
            // 定时器延时
            Timer timer = new Timer();
            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    Message msg = new Message();
                    msg.obj = 1;
                    if (!otherUtil.isVpnUsed()) {  // VPN服务器连接失败
                        msg.what = 0;
                    }else{
                        msg.what = 1;
                    }
                    handler2.sendMessage(msg);
                }
            }, time_delay);

        });

        //关闭连接 按钮
        Button button2 = findViewById(R.id.end);
        button2.setOnClickListener(v -> {
            // 关闭VPN service
            Intent intentStop = new Intent(MainActivity.this, a3cvpn.class);
            intentStop.putExtra(a3cvpn.VPN_TAG, a3cvpn.VPN_STOP);
            startService(intentStop);
            Toast.makeText(MainActivity.this, "已关闭连接", Toast.LENGTH_SHORT).show();
            //button1.setEnabled(true);  // 开放开始按钮
            button1.setBackgroundResource(R.drawable.bt_shape);  // 还原按钮样式
        });

        //打开文件存储目录 按钮
        Button button_file = findViewById(R.id.file);
        button_file.setOnClickListener(v -> {
            //唤起文件页面
            Intent intentfileview = new Intent(MainActivity.this, FileRead.class);
            startActivity(intentfileview);
        });

        //文本模块：软件使用说明
        TextView textView0 = findViewById(R.id.shuoming);
        textView0.setText(  "\n\n软件使用说明：\n\n" +
                            "1. 需允许VPN权限和文件读写权限\n\n" +
                            "2. 选择APP功能仅支持非系统应用，应用需在开始连接前选定，默认为全局启用\n\n" +
                            "3. 仅在网络连接正常且未开启VPN service时，可以开始连接，如果无法建立连接请重置网络\n\n" +
                            "4. 生成的pcap文件一般保存在Download/A3Cpcap/中，根据机型不同，文件保存位置可能有所变化\n\n" +
                            "5. PCAP文件命名格式为 年_月_日_时分秒__选择应用名（全局为all）\n\n" +
                            "6. PCAP文件预览默认显示前" + FileRead.packet_total + "条报文，且以IP头开始");
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {  // 若之前已存在VPN service
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == RESULT_OK) {
            Intent intentStart = new Intent(MainActivity.this, a3cvpn.class);
            intentStart.putExtra(a3cvpn.VPN_TAG, a3cvpn.VPN_START);
            //将配置信息传递给a3cvpn.class
//            intentStart.putExtra(a3cvpn.address_TAG, server_address);  //服务器地址（server_address1）
//            intentStart.putExtra(a3cvpn.port_TAG, server_port);  //服务器端口（server_port1）
//            intentStart.putExtra(a3cvpn.secret_TAG, secret);  //密钥（secret1）
            startService(intentStart);
        }
    }

    public static Handler handler = new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 0: {
                    button1.setBackgroundResource(R.drawable.bt_shape2);  //刷新按钮样式
                    break;
                }
            }
        }
    };

}