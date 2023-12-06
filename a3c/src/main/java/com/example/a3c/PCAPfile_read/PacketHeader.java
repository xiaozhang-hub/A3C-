package com.example.a3c.PCAPfile_read;

import com.example.a3c.function.fileFunc;

import java.text.SimpleDateFormat;
import java.util.Locale;

public class PacketHeader {
    /** 单位B：字节
     * 4B 时间戳高位
     * 4B 时间戳低位
     * 4B 报文总长度
     * 4B 报文总长度
     **/

    static final int off_time_high = 0;
    static final int off_time_low = 4;
    static final int off_packet_length = 8;

    public byte[] mData;
    public int mOffset;

    public PacketHeader(byte[] data, int offset) {
        mData = data;
        mOffset = offset;
    }

    // 获取报文总长度
    public int get_length() {  //获取报文长度
        return fileFunc.readInt(mData,mOffset + off_packet_length);
    }

    // 获取时间
    public String getTime() {
        long time_high = fileFunc.readInt(mData,mOffset + off_time_high);  // 获取时间戳高位
        long time_low = fileFunc.readInt(mData,mOffset + off_time_low);  // 获取时间戳低位
        long timestamp = time_high * 1000;
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(timestamp) + "." + time_low;
    }

}
