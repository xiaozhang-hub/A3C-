package com.example.a3c.PCAPfile_read;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import com.example.a3c.R;

import java.util.List;

public class PacketInfosAdapter extends BaseAdapter {
    Context context;
    List<PacketInfo> packet;

    public PacketInfosAdapter(Context context, List<PacketInfo> packetInfos) {
        this.context = context;
        this.packet = packetInfos;
    }

    @Override
    public int getCount() {
        int count = 0;
        if(null != packet) {
            return packet.size();
        }
        return count;
    }

    @Override
    public Object getItem(int position) {
        return packet.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        PacketInfosAdapter.ViewHolder1 viewHolder1;
        if(null == convertView) {
            viewHolder1 = new PacketInfosAdapter.ViewHolder1();
            LayoutInflater mInflater = LayoutInflater.from(context);
            convertView = mInflater.inflate(R.layout.pcapread_item, null);
            viewHolder1.pack_num = (TextView) convertView.findViewById(R.id.packet_num);
            viewHolder1.pack_time = (TextView) convertView.findViewById(R.id.packet_time);
            viewHolder1.c_protocol = (TextView) convertView.findViewById(R.id.in_protocal);
            viewHolder1.pack_length = (TextView) convertView.findViewById(R.id.packet_length);
            viewHolder1.s_addr = (TextView) convertView.findViewById(R.id.src_addr);
            viewHolder1.d_addr = (TextView) convertView.findViewById(R.id.des_addr);
            viewHolder1.s_port = (TextView) convertView.findViewById(R.id.src_port);
            viewHolder1.d_port = (TextView) convertView.findViewById(R.id.des_port);
            convertView.setTag(viewHolder1);
        } else {
            viewHolder1 = (PacketInfosAdapter.ViewHolder1)convertView.getTag();
        }
        if(null != packet) {
            viewHolder1.pack_num.setText(packet.get(position).getPacket_num());
            viewHolder1.pack_time.setText(packet.get(position).getPacket_time());
            viewHolder1.c_protocol.setText(packet.get(position).getIn_protocal());
            viewHolder1.pack_length.setText(packet.get(position).getPacket_length());
            viewHolder1.s_addr.setText(packet.get(position).getSrc_ip());
            viewHolder1.d_addr.setText(packet.get(position).getDes_ip());
            viewHolder1.s_port.setText(packet.get(position).getSrc_port());
            viewHolder1.d_port.setText(packet.get(position).getDes_port());
        }
        return convertView;
    }

    private class ViewHolder1 {
        TextView  pack_num;  // 报文序号
        TextView  pack_time;  // 时间
        TextView  c_protocol;  // 传输层协议
        TextView  pack_length;  // 报文长度
        TextView  s_addr;  // 源地址
        TextView  d_addr;  // 目的地址
        TextView  s_port;  // 源端口
        TextView  d_port;  // 目的端口
    }
}
