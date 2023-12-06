package com.example.a3c.PCAPfile_read;

public class PacketInfo {
    String packet_num;      // 报文序号
    String packet_time;     // 时间
    String in_protocal;     // 传输层协议
    String packet_length;   // 报文长度
    String src_ip;          // 源地址
    String des_ip;          // 目的地址
    String src_port;        // 源端口
    String des_port;        // 目的端口

    public PacketInfo(String packet_num, String packet_time, String in_protocal, String packet_length, String src_ip, String des_ip, String src_port, String des_port) {
        this.packet_num = packet_num;
        this.packet_time = packet_time;
        this.in_protocal = in_protocal;
        this.packet_length = packet_length;
        this.src_ip = src_ip;
        this.des_ip = des_ip;
        this.src_port = src_port;
        this.des_port = des_port;
    }

    public String getPacket_num() {
        return packet_num;
    }

    public void setPacket_num(String packet_num) {
        this.packet_num = packet_num;
    }

    public String getPacket_time() {
        return packet_time;
    }

    public void setPacket_time(String packet_time) {
        this.packet_time = packet_time;
    }

    public String getIn_protocal() {
        return in_protocal;
    }

    public void setIn_protocal(String in_protocal) {
        this.in_protocal = in_protocal;
    }

    public String getPacket_length() {
        return packet_length;
    }

    public void setPacket_length(String packet_length) {
        this.packet_length = packet_length;
    }

    public String getSrc_ip() {
        return src_ip;
    }

    public void setSrc_ip(String src_ip) {
        this.src_ip = src_ip;
    }

    public String getDes_ip() {
        return des_ip;
    }

    public void setDes_ip(String des_ip) {
        this.des_ip = des_ip;
    }

    public String getSrc_port() {
        return src_port;
    }

    public void setSrc_port(String src_port) {
        this.src_port = src_port;
    }

    public String getDes_port() {
        return des_port;
    }

    public void setDes_port(String des_port) {
        this.des_port = des_port;
    }

}
