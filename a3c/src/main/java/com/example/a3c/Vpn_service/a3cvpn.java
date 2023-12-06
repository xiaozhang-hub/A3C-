package com.example.a3c.Vpn_service;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.example.a3c.MainActivity;
import com.example.a3c.function.fileFunc;

import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.Selector;
import java.util.Arrays;
import java.io.IOException;
import java.net.InetAddress;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.example.a3c.model.ByteBufferPool;
import com.example.a3c.model.Packet;
import com.example.a3c.net.*;

import static com.example.a3c.function.fileFunc.intToByteLittle;
import static com.example.a3c.function.fileFunc.writeHead;

public class a3cvpn extends VpnService {
    private static final String TAG = "A3C-vpn-service";
    public static final String VPN_TAG = "vpn_tag";  //VPN服务
    public static final int VPN_START = 1;
    public static final int VPN_STOP = -1;
    public static String SP_TAG = "sp_tag";
    public static String SP2_TAG = "sp2_tag";
    public static final String APP_TAG = "app_tag";  //使用VPN的包名
    public static final String APPname_TAG = "app_tag";  //使用VPN的应用名

    //VPN参数配置
//    public static final String address_TAG = "address_tag";  //配置服务器地址
//    public static final String port_TAG = "port_tag";  //配置服务器端口
//    public static final String secret_TAG = "secret_tag";  //配置密钥
    private static final String VPN_ADDRESS = "10.0.0.2";
    private static final int VPN_ADDRESS_MASK = 32;
    private static final String VPN_ROUTE = "0.0.0.0";
    private static final int VPN_ROUTE_MASK = 0;
    private static final int VPN_MTU = 1500;

    // TCP 流控模式
    private static final boolean DEFAULT_IS_TCP_FLOW_MODE_SPY = true;
    private static final boolean DEFAULT_IS_UDP_FLOW_MODE_SPY = true;
    private boolean isTcpFlowModeSpy = true;
    private boolean isUdpFlowModeSpy = true;

    // 运行状态
    private static boolean running = false;

    // 队列
    private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
    private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;
    // 线程池
    private ExecutorService executorService;

    // TCP、UDP选择器 /* 监控通道状态，Channel.register注册到选择器上 */
    private Selector udpSelector;
    private Selector tcpSelector;

    private Thread mThread;  //线程
    private ParcelFileDescriptor parcelFileDescriptor = null;  //接收文件描述符
    private String mServerAddress;  //服务器地址
    private String mServerPort;  //服务器端口
    private PendingIntent mConfigureIntent;
    public String secret;  //密钥
    private byte[] mSharedSecret;  //密钥比特流形式
    private String mParameters;  //参数
    public File file1;  // pcap文件
    private FileOutputStream f; //文件流
    public String app_choose = null;  //选择包名
    public String app_choose_name = null;  //选择应用名
    public SharedPreferences sp;
    public SharedPreferences sp2;

    public a3cvpn() {
        super();
        Log.d(TAG, "VPN service已创建");
    }

    @Override
    public void onRevoke() {  // 停止VPN
        super.onRevoke();
        Log.d(TAG, "VPN service已停止");
    }

//    @Override
//    public void onDestroy() {  //销毁service
//        super.onDestroy();
//        if (mThread != null) {
//            mThread.interrupt();
//        }
//        Log.d(TAG, "VPN service已销毁");
//    }


    @Override
    public void onDestroy() {
        super.onDestroy();
        running = false;
        executorService.shutdownNow();
        clean();
        Log.i(TAG, "FirewallVpnService Stopped");
    }

    // 清理函数
    private void clean() {
        this.deviceToNetworkUDPQueue = null;
        this.deviceToNetworkTCPQueue = null;
        this.networkToDeviceQueue = null;
        ByteBufferPool.clear();
        closeResource(udpSelector, tcpSelector, parcelFileDescriptor);
    }

    // 清理资源
    private static void closeResource(Closeable... resources) {
        for (Closeable resource : resources) {
            try {
                resource.close();
            } catch (Exception e) {
                e.printStackTrace();
                Log.i(TAG, "Clean resources failed");
            }
        }
    }


    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        int tag = intent.getIntExtra(VPN_TAG, VPN_STOP);
        if (tag == VPN_START) {
            // 设置运行状态
            a3cvpn.running = true;

            // 建立 VPN 连接
            if (this.parcelFileDescriptor == null) {
                // 设置参数
                Builder builder = new Builder();
                builder.addAddress(VPN_ADDRESS, VPN_ADDRESS_MASK);
                builder.addRoute(VPN_ROUTE, VPN_ROUTE_MASK);
                builder.setMtu(VPN_MTU);

                // 建立连接
                this.parcelFileDescriptor = builder.establish();
            }

            try {
                // 配置选择器
                udpSelector = this.isUdpFlowModeSpy ? Selector.open() : null;
                tcpSelector = this.isTcpFlowModeSpy ? Selector.open() : null;

                // 创建队列
                if (this.isUdpFlowModeSpy) deviceToNetworkUDPQueue = new ConcurrentLinkedQueue<>();
                if (this.isTcpFlowModeSpy) deviceToNetworkTCPQueue = new ConcurrentLinkedQueue<>();
                networkToDeviceQueue = new ConcurrentLinkedQueue<>();

                // 创建线程池
                executorService = Executors.newFixedThreadPool(
                        5 - (this.isTcpFlowModeSpy ? 0 : 2) - (this.isUdpFlowModeSpy ? 0 : 2)
                );

                // 每一个线程负责一个任务 /* submit分配线程，如果被分配到的线程空闲，将立即执行 */
                if (this.isUdpFlowModeSpy) {
                    /* 将在UDPOutput线程中注册的通道中收到的数据写入networkToDeviceQueue */
                    executorService.submit(new UDPInput(networkToDeviceQueue, udpSelector));
                    /* 将deviceToNetworkUDPQueue的数据写回通道，并注册通道、记录最近使用的通道 */
                    executorService.submit(new UDPOutput(deviceToNetworkUDPQueue, udpSelector, this));
                }
                if (this.isTcpFlowModeSpy) {
                    /* 处理未完成连接的通道
                     * 向networkToDeviceQueue写入连接控制数据
                     * 接收通道数据，打包首部后写入networkToDeviceQueue */
                    executorService.submit(new TCPInput(networkToDeviceQueue, tcpSelector));
                    /* 建立deviceToNetworkTCPQueue的连接，注册通道（未完成连接时；完成连接且ACK=1时），
                     * 向networkToDeviceQueue写入连接控制数据，代替传输层建立连接
                     * ACK=1时，将deviceToNetworkTCPQueue的数据写回通道*/
                    executorService.submit(new TCPOutput(deviceToNetworkTCPQueue, networkToDeviceQueue, tcpSelector, this));
                }
                /* 向deviceToNetworkUDPQueue、deviceToNetworkTCPQueue写入包；将networkToDeviceQueue中的包写回设备 */
                executorService.submit(new VPNRunnable(
                        parcelFileDescriptor.getFileDescriptor(),
                        deviceToNetworkUDPQueue,
                        deviceToNetworkTCPQueue,
                        networkToDeviceQueue,
                        isUdpFlowModeSpy,
                        isTcpFlowModeSpy
                ));

                Log.i(TAG, "FirewallVpnService Started");
            } catch (IOException e) {
                e.printStackTrace();
                Log.e(TAG, "Can't start FirewallVpnService");

                // 清理
                clean();
            }
        }else {  // tag为STOP，关闭连接
            try {
                if (parcelFileDescriptor != null) {
                    parcelFileDescriptor.close();  //关闭文件描述符
                    parcelFileDescriptor = null;  //清空文件描述符
                }
            } catch (Exception e) {

            }
            onRevoke();
        }

        return START_STICKY;
    }

    // Vpn 服务线程
    private static class VPNRunnable implements Runnable {

        private static final String TAG = "RFF-VpnThread";

        // 文件描述符
        private FileDescriptor fileDescriptor;

        // 队列
        private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
        private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
        private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;

        // 流控模式
        private boolean isUdpFlowModeSpy;
        private boolean isTcpFlowModeSpy;

        // 构造
        public VPNRunnable(
                FileDescriptor fileDescriptor,
                ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue,
                ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue,
                ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue,
                boolean isUdpFlowModeSpy,
                boolean isTcpFlowModeSpy
        ) {
            this.fileDescriptor = fileDescriptor;
            this.deviceToNetworkUDPQueue = deviceToNetworkUDPQueue;
            this.deviceToNetworkTCPQueue = deviceToNetworkTCPQueue;
            this.networkToDeviceQueue = networkToDeviceQueue;
            this.isUdpFlowModeSpy = isUdpFlowModeSpy;
            this.isTcpFlowModeSpy = isTcpFlowModeSpy;
        }

        @Override
        public void run() {
            Log.i(VPNRunnable.TAG, "VPN thread started");

            // 获取 channel
            FileChannel vpnInput = new FileInputStream(fileDescriptor).getChannel();
            FileChannel vpnOutput = new FileOutputStream(fileDescriptor).getChannel();

            try {
                // 创建发送缓冲区
                ByteBuffer bufferToNetwork = null;
                boolean dataSent = true;
                boolean dataReceived;

                // 开始循环 /* 收一个包发一个包 */
                while (!Thread.interrupted()) {
                    if (dataSent) {
                        // 如果已经发送了数据，则从缓冲池中获取一个缓冲区
                        bufferToNetwork = ByteBufferPool.acquire();
                    } else {
                        // 如果还没发送，则先清空
                        bufferToNetwork.clear();
                    }

                    // 读取一个来自物理网卡的数据包
                    int readLength = vpnInput.read(bufferToNetwork);
                    if (readLength > 0) {
                        // 如果读取到了数据
                        Log.i(VPNRunnable.TAG, "get a ip packet");
                        dataSent = true;

                        // 在读取数据前先将 limit 设置为 position，position 设置为 0
                        bufferToNetwork.flip();

                        // 拆包
                        Packet packet = new Packet(bufferToNetwork);

                        // 判断包的种类
                        if (packet.isUDP()) {
                            // 如果是 UDP 包
                            Log.i(VPNRunnable.TAG, "it's a UDP packet");
                            // 在队列中加入包
                            if (this.isUdpFlowModeSpy) deviceToNetworkUDPQueue.offer(packet);
                        } else if (packet.isTCP()) {
                            // 如果是 TCP 包
                            Log.i(VPNRunnable.TAG, "it's a TCP packet");
                            // 在队列中加入包
                            if (this.isTcpFlowModeSpy) deviceToNetworkTCPQueue.offer(packet);
                        } else {
                            // 如果是其他包
                            Log.i(VPNRunnable.TAG, "it's a unknown type packet");
                            Log.i(VPNRunnable.TAG, packet.ip4Header.toString());
                            dataSent = false;
                        }
                    } else {
                        // 如果没有读取到数据
                        dataSent = false;
                    }

                    // 每次都尝试从收外部网络的队列取走一个数据包
                    ByteBuffer bufferFromNetwork = networkToDeviceQueue.poll();/* poll获取并移除头部元素 */
                    // 如果拿到了数据
                    if (bufferFromNetwork != null) {
                        // 准备读取
                        bufferFromNetwork.flip();
                        // 将数据一股脑写回物理网卡
                        vpnOutput.write(bufferFromNetwork);
                        // 设置收到数据标识
                        dataReceived = true;
                        // 从缓冲池中释放缓冲区
                        ByteBufferPool.release(bufferFromNetwork);
                    } else {
                        dataReceived = false;
                    }

                    // 无收也无发，则让线程睡一会
                    if (!dataSent && !dataReceived) {
                        Thread.sleep(10);
                    }
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
                Log.e(VPNRunnable.TAG, "get a interrupted exception");
            } catch (IOException e) {
                e.printStackTrace();
                Log.e(VPNRunnable.TAG, "get a IO exception");
            } catch (Exception e) {
                e.printStackTrace();
                Log.e(VPNRunnable.TAG, "get a exception");
            } finally {
                closeResource(vpnInput, vpnOutput);
            }
        }
    }


    public static boolean isRunning() {
        return running;
    }

}



//    @Override
//    public int onStartCommand(Intent intent, int flags, int startId) {
//        int tag = intent.getIntExtra(VPN_TAG, VPN_STOP);  //缺省值为STOP
//        if (tag == VPN_START) {
//            if (mThread != null) {
//                mThread.interrupt();
//            }
//            // 启动VPN连接
//            try {
//                // 配置VpnService参数
//                Builder builder = new Builder();
//                mInterface = builder.addAddress("10.0.0.1", 24)
//                        .addRoute("0.0.0.0", 0)
//                        .setSession("MyVPNService")
//                        .setConfigureIntent(mConfigureIntent)
//                        .establish();
//
//                // 用于处理数据包的线程
//                mThread = new Thread(this::runVpnConnection, "VpnThread");
//                mThread.start();
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        } else {  // tag为STOP，关闭连接
//            try {
//                if (mInterface != null) {
//                    mInterface.close();  //关闭文件描述符
//                    mInterface = null;  //清空文件描述符
//                }
//            } catch (Exception e) {
//
//            }
//            onRevoke();
//        }
//        return START_STICKY;
//    }

//    private void runVpnConnection() {
//        try {
//            while (!Thread.interrupted()) {
//                // 接收数据包
//                FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
//                FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());
//                ByteBuffer packet = ByteBuffer.allocate(32767);
//
//                // 接收数据包
//                int length = in.read(packet.array());
//                Log.d("VPN test", "Received a packet");
//                packet.limit(length);
//                if (length > 0) {
//                    // 解析IP首部
//                    byte version_num = (byte) ((packet.get(0) & 0xFF) >> 4);
//                    if(version_num == 4) {
//                        byte[] sourceAddressBytes = new byte[4];
//                        packet.position(12); // 源IP地址在第12字节开始
//                        packet.get(sourceAddressBytes);
//                        InetAddress sourceAddress = InetAddress.getByAddress(sourceAddressBytes);
//
//                        // 获取目标IP地址
//                        byte[] destinationAddressBytes = new byte[4];
//                        packet.position(16); // 目标IP地址在第16字节开始
//                        packet.get(destinationAddressBytes);
//                        InetAddress destinationAddress = InetAddress.getByAddress(destinationAddressBytes);
//
//                        int identification = ((packet.get(4) & 0xFF) << 8) | (packet.get(5) & 0xFF); //清除符号位
//
//                        Log.d("Received packet", "Source: " + sourceAddress.getHostAddress() +
//                                " Destination: " + destinationAddress.getHostAddress() +
//                                " Identification: " + identification);
//
//                        // 修改IP首部的标识字段
//                        identification |= 0xE000;  //前三位置1
//                        packet.put(4, (byte) ((identification >> 8) & 0xFF));
//                        packet.put(5, (byte) (identification & 0xFF));
//                    } else if(version_num == 6){
//                        Log.d("Received packet" , "ipv6包");
//                    }
//
//                    // 发送修改后的数据包
//                    out.write(packet.array(), 0, length);
//                }
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//}


