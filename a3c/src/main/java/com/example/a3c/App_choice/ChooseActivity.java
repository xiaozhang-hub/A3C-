package com.example.a3c.App_choice;

import android.app.Activity;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.widget.ListView;
import android.widget.Toast;

import com.example.a3c.R;
import com.example.a3c.Vpn_service.a3cvpn;

import java.util.ArrayList;
import java.util.List;

public class ChooseActivity extends Activity {
    //选择APP的页面
    ListView appInfoListView = null;
    List<AppInfo> appInfos = null;
    AppInfosAdapter infosAdapter = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.appchoose_list);  //显示在新页面
        appInfoListView = this.findViewById(R.id.applist);  //显示在列表中
        appInfos = getAppInfos();
        updateUI(appInfos);  //刷新列表

        final AppInfosAdapter adapter = new AppInfosAdapter(ChooseActivity.this, appInfos);
        appInfoListView.setAdapter(adapter);
        //item的点击事件
        appInfoListView.setOnItemClickListener((adapterView, view, index, l) -> {
            String packname = appInfos.get(index).getPackageName();  //获取包名
            String appname = appInfos.get(index).getAppName();  //获取应用名
            //传递信息
            SharedPreferences sp = ChooseActivity.this.getSharedPreferences(a3cvpn.SP_TAG, MODE_PRIVATE);
            SharedPreferences.Editor editor = sp.edit();
            editor.putString(a3cvpn.APP_TAG, packname);  //传递包名
            editor.commit();  //提交信息
            SharedPreferences sp2 = ChooseActivity.this.getSharedPreferences(a3cvpn.SP2_TAG, MODE_PRIVATE);
            SharedPreferences.Editor editor2 = sp2.edit();
            editor2.putString(a3cvpn.APPname_TAG, appname);  //传递应用名
            editor2.commit();  //提交信息
            Toast.makeText(ChooseActivity.this, "选择应用：" + appname, Toast.LENGTH_SHORT).show();
            finish();  //回退至主页面
        });
    }

    public void updateUI(List<AppInfo> appInfos){  //刷新列表
        if(null != appInfos){
            infosAdapter = new AppInfosAdapter(getApplication(), appInfos);
            appInfoListView.setAdapter(infosAdapter);
        }
    }

    // 获取应用信息列表
    public List<AppInfo> getAppInfos(){
        PackageManager pm = getApplication().getPackageManager();
        List<PackageInfo> packageInfos = pm.getInstalledPackages(PackageManager.GET_ACTIVITIES | PackageManager.GET_SERVICES);
        appInfos = new ArrayList<AppInfo>();
    	/* 获取应用程序的名称，不是包名，而是清单文件中的labelname
			String str_name = packageInfo.applicationInfo.loadLabel(pm).toString();
			appInfo.setAppName(str_name);
    	 */
        for(PackageInfo packageInfo : packageInfos){
            // 读取已安装应用
            /*
            String appName = packageInfo.applicationInfo.loadLabel(pm).toString();  //应用名
            String packageName = packageInfo.packageName;  //包名
            Drawable icon = packageInfo.applicationInfo.loadIcon(pm);  //图标
            AppInfo appInfo = new AppInfo(appName, packageName, icon);
            appInfos.add(appInfo);
             */
            if ((packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0) {  //非系统应用
                String appName = packageInfo.applicationInfo.loadLabel(pm).toString();  //应用名
                String packageName = packageInfo.packageName;  //包名
                Drawable icon = packageInfo.applicationInfo.loadIcon(pm);  //图标
                AppInfo appInfo = new AppInfo(appName, packageName, icon);
                appInfos.add(appInfo);
            } else {
                // 系统应用
            }
        }
        return appInfos;
    }
}
