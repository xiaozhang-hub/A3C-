package com.example.a3c.PCAPfile_read;

import com.example.a3c.function.fileFunc;

public class IPHeader {

    /**
     * IPv4报文格式（单位比特，1字节=8比特）
     * 0                                   　　　　       15  16　　　　　　　　　　　　　　　　　　　　　　　　   31
     * ｜　－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
     * ｜  ４　位     ｜   ４位首     ｜      ８位服务类型      ｜      　　         １６位总长度            　   ｜
     * ｜  版本号     ｜   部长度     ｜      （ＴＯＳ）　      ｜      　 　 （ｔｏｔａｌ　ｌｅｎｇｔｈ）    　    ｜
     * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
     * ｜  　　　　　　　　１６位标识符                         ｜　３位    ｜　　　　１３位片偏移                 ｜
     * ｜            （ｉｎｄｅｎｔｉｆｉｅｒ）                 ｜　标志    ｜      （ｏｆｆｓｅｔ）　　           ｜
     * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
     * ｜      ８位生存时间ＴＴＬ      ｜       ８位协议        ｜　　　　　　　　１６位首部校验和                  ｜
     * ｜（ｔｉｍｅ　ｔｏ　ｌｉｖｅ）　　｜   （ｐｒｏｔｏｃｏｌ） ｜              （ｃｈｅｃｋｓｕｍ）               ｜
     * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
     * ｜                              ３２位源ＩＰ地址（ｓｏｕｒｃｅ　ａｄｄｒｅｓｓ）                           ｜
     * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
     * ｜                         ３２位目的ＩＰ地址（ｄｅｓｔｉｎａｔｉｏｎ　ａｄｄｒｅｓｓ）                     ｜
     * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
     * ｜                                          ３２位选项（若有）                                        ｜
     * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
     * ｜                                                                                                  ｜
     * ｜                                               数据                                               ｜
     * ｜                                                                                                  ｜
     * ｜－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－－｜
     **/

    public static final byte version4 = 4;  // IPv4版本号
    public static final byte version6 = 6;  // IPv6版本号
    public static final byte ICMP = 1;  // ICMP协议号
    public static final byte TCP = 6;  // TCP协议号
    public static final byte UDP = 17; // UDP协议号
    public static final byte ICMPv6 = 58; // ICMPv6协议号
    public static final byte off_version = 0; // IP层协议版本号偏移
    public static final byte off_protocol4 = 9; // v4传输层协议号偏移
    public static final byte off_protocol6 = 6; // v6传输层协议号偏移
    public static final byte off_srcip4 = 12; // v4源地址偏移
    public static final byte off_desip4 = 16; // v4目的地址偏移
    public static final byte off_srcip6 = 8; // v6源地址偏移
    public static final byte off_desip6 = 24; // v6目的地址偏移
    public static final byte src = 0;  //源
    public static final byte des = 1;  //目的
    public byte[] mData;  // 数据流
    public int mOffset;  // 初始偏移量
    public byte version;  // IP层协议版本号

    public static final byte off_srcport = 0; // 传输层源端口偏移
    public static final byte off_desport = 2; // 传输层目的端口偏移

    public IPHeader(byte[] data, int offset) {
        mData = data;
        mOffset = offset;
        version = get_version_num();
    }

    // 获取是IPv4 or IPv6
    public byte get_version_num() {
        byte version_num = (byte) (mData[mOffset + off_version] >> 4);
        return version_num;
    }

    public String get_version() {
        if (version == version4) {
            return "IPv4";
        }
        else if (version == version6) {
            return "IPv6";
        }
        else {
            return "NaN";
        }
    }

    // 获取IPv4报文IP头部长度
    public int get4HeaderLength() { return (mData[mOffset + off_version] & 0x0F) * 4; }

    // 获取传输层协议
    public String get_protocol() {
        // 判断v4 or v6
        byte off_protocol;
        if (version == version4) {
            off_protocol = off_protocol4;
        }
        else if (version == version6) {
            off_protocol = off_protocol6;
        }
        else {
            return "NaN";
        }
        // 读取传输层协议字段
        byte protocal = mData[mOffset + off_protocol];
        if (protocal == TCP) {
            return "TCP";
        }
        else if (protocal == UDP) {
            return "UDP";
        }
        else if (protocal == ICMP) {
            return "ICMP";
        }
        else if (protocal == 0 && mData[mOffset + 40] == ICMPv6) {  //next header或扩展报头
            return "ICMPv6";
        }
        else {
            return "NaN";
        }
    }

    // 获取IP地址（源地址或目标地址）
    public String get_ip(byte type) {
        byte off_ip;
        String ip;
        if (version == version4) {
            // 判断源地址or目标地址
            if (type == src) {  // 源地址
                off_ip = off_srcip4;
            } else {            // 目标地址
                off_ip = off_desip4;
            }
            int src1 = mData[mOffset + off_ip] & 0xFF;
            int src2 = mData[mOffset + off_ip + 1] & 0xFF;
            int src3 = mData[mOffset + off_ip + 2] & 0xFF;
            int src4 = mData[mOffset + off_ip + 3] & 0xFF;
            ip = String.format("%s.%s.%s.%s", src1, src2, src3, src4);
            return ip;
        } else if (version == version6) {
            if (type == src) {  // 源地址
                off_ip = off_srcip6;
            } else {            // 目标地址
                off_ip = off_desip6;
            }
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < 16; i++)
            {
                int v = mData[mOffset + off_ip + i] & 0xFF;
                String hv = Integer.toHexString(v);
                if (hv.length() < 2) {
                    stringBuilder.append(0);
                }
                stringBuilder.append(hv);
                if (i % 2 == 1 && i != 15) {
                    stringBuilder.append(":");
                }
            }
            return stringBuilder.toString();
        } else {
            return "NaN";
        }
    }

    // 获取IP报文长度，寻找传输层报文头部位置
    public int get_port(byte type) {
        byte off_port;
        if (version == version4) {
            int ipheader_length = get4HeaderLength();
            // 判断源地址or目标地址
            if (type == src) {  // 源端口
                off_port = off_srcport;
            } else {            // 目的端口
                off_port = off_desport;
            }
            return fileFunc.readShort(mData, mOffset + ipheader_length + off_port);
        }
        else {
            return 0;
        }
    }

}
