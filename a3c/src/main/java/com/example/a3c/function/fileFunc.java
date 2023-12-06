package com.example.a3c.function;

import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;


public class fileFunc {
    public static final String file_TAG = "File";
    public static final String dir_name = "/A3Cpcap/";
    // 在外部存储中创建pcap文件
    public static File newDownFile(String app_choose_name) {
        // 判断外部存储是否可用
        if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {
            File exfile = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            //文件命名为时间（秒）
            long currentTime = System.currentTimeMillis();
            String timeNow = new SimpleDateFormat("yyyy_MM_dd_HH:mm:ss").format(currentTime);
            String filename0 = timeNow.replace(":", "");  //文件名中不能存在冒号
            String filename = filename0 + "__" + app_choose_name;
            // 实例化文件对象
            File file1 = new File(exfile + dir_name);
            File file2 = new File(exfile + dir_name,filename + ".pcap");
            // 文件如果已经存在，则删除已有文件
            if (file2.exists()) {
                file2.delete();
                Log.e(file_TAG, "删除已有pcap文件");
            }
            // 创建文件目录
            if (!file1.exists()) {
                if(file1.mkdirs())
                    Log.e(file_TAG, "目录创建成功");
            }
            // 创建空pcap文件
            try {  // 创建pcap文件
                if(file2.createNewFile()) {
                    Log.d(file_TAG, "文件创建成功，路径为：" + exfile + dir_name + filename + ".pcap");
                    return file2;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            Log.e(file_TAG, "外部存储不可用" );
        }
        return null;
    }

    public static void writeHead(File file) {  // 写入pcap文件头部
        if(file.exists()) {
            try {
                FileOutputStream f = new FileOutputStream(file);  //创建文件流
                //写入文件头部
                //小端模式
                f.write(0xd4);
                f.write(0xc3);
                f.write(0xb2);
                f.write(0xa1);
                //一些固定值
                f.write(0x02);
                f.write(0);
                f.write(0x04);
                f.write(0);
                for (int i = 1;i < 9; i++) { f.write(0); }  //8字节0
                //最大抓取报文长度（固定值）
                f.write(0xdc);
                f.write(0x05);
                f.write(0);
                f.write(0);
                //链路类型为纯IP报文
                f.write(0x65);
                for (int i = 1;i < 4;i++) { f.write(0); }  //3字节0
                f.flush();  //刷新文件流
                f.close();  //关闭文件流
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static byte[] intToByteLittle(int n) {  //int转为byte[]（小端）
        byte[] b = new byte[4];
        b[0] = (byte) (n & 0xff);
        b[1] = (byte) (n >> 8 & 0xff);
        b[2] = (byte) (n >> 16 & 0xff);
        b[3] = (byte) (n >> 24 & 0xff);
        return b;
    }

    public static int ByteLittleToint(byte[] b) {  //byte[]（小端）转为int
        return  (b[3] & 0xFF) << 24|
                (b[2] & 0xFF) << 16 |
                (b[1] & 0xFF) << 8 |
                (b[0] & 0xFF) ;
    }

    public static int readInt(byte[] data, int offset) {  // 读取int（4字节，小端）
        int r = ((data[offset + 3] & 0xFF) << 24)
                | ((data[offset+ 2] & 0xFF) << 16)
                | ((data[offset + 1] & 0xFF) << 8)
                | (data[offset] & 0xFF);
        return r;
    }

    public static int readShort(byte[] data, int offset) {  // 读取short（2字节，小端）
        int r = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        return r;
    }

    public static void StreamSkip(FileInputStream fis, long k)
    {
        while(k > 0) {
            long realSkip = 0;
            try {
                realSkip = fis.skip(k);
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (realSkip == -1) {
                throw new RuntimeException("Unexpected EOF: Skip Error");
            }
            k -= realSkip;
        }
    }

}