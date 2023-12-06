package com.example.a3c.PCAPfile_read;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.DocumentsContract;
import android.util.Log;
import android.widget.ListView;

import androidx.annotation.RequiresApi;

import com.example.a3c.R;
import com.example.a3c.function.fileFunc;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.List;

public class FileRead extends Activity {
    String path = "%2fDownload%2fA3Cpcap%2f";  // 用 %2f 代替 /
    Uri uri = Uri.parse("content://com.android.externalstorage.documents/document/primary:" + path);
    public ListView packetListView;
    public static int packet_total = 300; // 显示报文数量上限
    public List<PacketInfo> PacketInfos = null;
    public PacketInfosAdapter packetinfosAdapter = null;
    private static final Handler handler = new Handler(Looper.getMainLooper());

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.pcapread_list);
        packetListView = this.findViewById(R.id.packetlist);  //显示在列表中
        // 打开PCAP文件存储目录
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");//想要展示的文件类型
        intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, uri);
        startActivityForResult(intent, 0);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == Activity.RESULT_OK) {
            Uri uri_pcap = data.getData();  // 定位至PCAP文件
            path = uri_pcap.getPath();
            // 使用第三方应用打开文件
            try {
                PacketInfos = getpacketInfos(path);
            } catch (Exception e) {
                e.printStackTrace();
            }
            updateUI(PacketInfos);  //刷新列表
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    // 获取应用信息列表
    public List<PacketInfo> getpacketInfos(String fileName) {
        List<PacketInfo> packetInfos = new ArrayList<>();
        if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {
            // 修改文件路径为真实路径
            File exfile = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            String file_0 = exfile + "/";
            fileName = fileName.replaceAll("document/primary:Download/", file_0);
            try {
                File file = new File(fileName);
                FileInputStream fis = new FileInputStream(file);
                // 读取数据包长度
                fileFunc.StreamSkip(fis, 24);  // 跳过PCAP头部24字节
                int packet_num = 0;  // 报文数
                while (packet_num < packet_total) {
                    packet_num++;  // 报文序号
                    // PCAP文件头部
                    byte[] tbuffer = new byte[16];
                    fis.read(tbuffer);
                    PacketHeader packetHeader = new PacketHeader(tbuffer, 0);
                    String packet_time = packetHeader.getTime();            // 时间
                    int packet_length = packetHeader.get_length();          // 报文长度
                    // 读取报文
                    byte[] packet_ip = new byte[packet_length];
                    fis.read(packet_ip);
                    // 解析IP报头（目前仅支持IPv4解析）
                    IPHeader ipHeader = new IPHeader(packet_ip, 0);
                    String in_protocal = ipHeader.get_protocol();           // 传输层协议
                    String src_ip = ipHeader.get_ip(IPHeader.src);          // 源地址
                    String des_ip = ipHeader.get_ip(IPHeader.des);          // 目的地址
                    // 解析传输层报头
                    int src_port = ipHeader.get_port(IPHeader.src);         // 源端口
                    int des_port = ipHeader.get_port(IPHeader.des);         // 目的端口
                    PacketInfo packetInfo = new PacketInfo(packet_num+"", packet_time, in_protocal, packet_length+"", src_ip, des_ip, src_port+"", des_port+"");
                    packetInfos.add(packetInfo);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            Log.e(fileFunc.file_TAG, "外部存储不可用");
        }
        return packetInfos;
    }

    public void updateUI(List<PacketInfo> packetInfos) {  //刷新列表
        if(null != packetInfos) {
            packetinfosAdapter = new PacketInfosAdapter(FileRead.this, packetInfos);
            handler.post(new Runnable() {
                @Override
                public void run() {
                    packetListView.setAdapter(packetinfosAdapter);
                }
            });
        }
    }
}

