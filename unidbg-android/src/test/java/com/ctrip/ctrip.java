package com.ctrip;

import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.ApplicationInfo;
import com.github.unidbg.linux.android.dvm.api.AssetManager;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.IO;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneMode;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


// 1、继承关系
public class ctrip extends AbstractJni implements IOResolver {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    ctrip() {
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("ctrip.android.view").build(); // 创建模拟器实例
        //2、 绑定IO重定向接口
        emulator.getSyscallHandler().addIOResolver(this);
        final Memory memory = emulator.getMemory(); // 模拟器的内存操作接口
        memory.setLibraryResolver(new AndroidResolver(23)); // 设置系统类库解析
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/java/com/ctrip/xc_8.35.3.apk")); // 创建Android虚拟机

        new AndroidModule(emulator, vm).register(memory);

        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/java/com/ctrip/libscmain_8.35.3.so"), true); // 加载so到虚拟内存
        module = dm.getModule(); //获取本SO模块的句柄
        System.out.println(module.toString());

        vm.setJni(this);
        vm.setVerbose(true);
        dm.callJNI_OnLoad(emulator);
    }


    /**
     * libscmain_8.38.2
     */
    public void callsimpleSign() {
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(0);
        String input = "7be9f13e7f5426d139cb4e5dbb1fdba7";
        byte[] inputbyte = input.getBytes(StandardCharsets.UTF_8);
        ByteArray inputbytearry = new ByteArray(vm, inputbyte);
        list.add(vm.addLocalObject(inputbytearry));
        list.add(vm.addLocalObject(new StringObject(vm, "getdata")));
        Number number = module.callFunction(emulator, 0x869d9, list.toArray())[0];
        System.out.println(vm.getObject(number.intValue()).getValue().toString());

    }

    public void patch2() {
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, module.base + 0x0006dd16);
        Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb);
        String s = "nop";
        byte[] machineCode = keystone.assemble(s).getMachineCode();
        // System.out.println(Integer.toHexString(machineCode[3]));
        pointer.write(machineCode);
    }

    public void callInit(){
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(0);
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);// context
        list.add(vm.addLocalObject(context));
        module.callFunction(emulator, 0x311e1|1, list.toArray());
    };

    public void callgetNameByPid() {
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(0);
        list.add(emulator.getPid());
        Number number = module.callFunction(emulator, 0xd7bd | 1, list.toArray())[0];
        String name = vm.getObject(number.intValue()).getValue().toString();
        System.out.println(name);
    }

    private void call_getToken() {
        System.out.println("call_getToken entry============");
//        patch2();

        Debugger debugger = emulator.attach();
//        debugger.addBreakPoint(module, 0x00066bae);
//        debugger.addBreakPoint(module, 0x0006dd16);

        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.replace(module.findSymbolByName("popen"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("popen_LR: " + context.getLRPointer());
                UnidbgPointer p1 = context.getPointerArg(0);
                String wht = p1.getString(0);
                Inspector.inspect(wht.getBytes(), "popenstring");
                return HookStatus.LR(emulator, 0);
            }
        });

        // coord: (0,358,26) | addr: Lctrip/android/security/SecurityUtil;->getToken()Ljava/lang/String; | loc: ?
        DvmClass classSecurityUtil = vm.resolveClass("ctrip/android/security/SecurityUtil");
        // coord: (0,321,38) | addr: Lctrip/android/security/SecurityUtil;->getInstance()Lctrip/android/security/SecurityUtil; | loc: ?
//        DvmObject<?> inst = classSecurityUtil.callStaticJniMethodObject(emulator, "getInstance()Lctrip/android/security/SecurityUtil;");
        // coord: (654500,0,31) | addr: Lctrip/android/security/SecurityUtil;->init(Landroid/content/Context;)V | loc: ?
        DvmObject<?> inst = classSecurityUtil.newObject(null);
//        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
//        inst.callJniMethod(emulator, "init(Landroid/content/Context;)V", context);
        DvmObject<?> res = inst.callJniMethodObject(emulator, "getToken()Ljava/lang/String;");
        System.out.println("done!");


//        int popenAddress = (int) module.findSymbolByName("popen").getAddress();
//        emulator.attach().addBreakPoint(popenAddress, new BreakPointCallback() {
//            @Override
//            public boolean onHit(Emulator<?> emulator, long address) {
//                RegisterContext registerContext = emulator.getContext();
//                String cmdline = registerContext.getPointerArg(0).getString(0);
//                System.out.println("fuck popen cmdline:"+cmdline);
//                return true;
//            }
//        });

//        emulator.traceCode();
//        List<Object> list = new ArrayList<>(10);
//        list.add(vm.getJNIEnv());
//        list.add(0);
//        Number number = module.callFunction(emulator, 0x66b5d, list.toArray())[0];
//        System.out.println(vm.getObject(number.intValue()).getValue().toString());
    }

    public static void main(String[] args) throws Exception {
//        Logger.getLogger("com.github.unidbg.linux.ARM32SyscallHandler").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.unix.UnixSyscallHandler").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.linux.android.dvm.DalvikVM").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.linux.android.dvm.BaseVM").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.linux.android.dvm").setLevel(Level.DEBUG);
        ctrip test = new ctrip();
        System.out.println("call init");
        test.callInit();
//        test.callsimpleSign();
        System.out.println("call getToken");
        test.call_getToken();
//        test.callgetNameByPid();
    }

    //3、
    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        System.out.println("访问：" + pathname);
        if (("proc/" + emulator.getPid() + "/cmdline").equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, "ctrip.android.view".getBytes()));
        }
        if (("proc/" + emulator.getPid() + "/status").equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                    ("Name:   ip.android.view\n" +
                    "State:  S (sleeping)\n" +
                    "Tgid:   " + emulator.getPid() + "\n" +
                    "Pid:    " + emulator.getPid() + "\n" +
                    "PPid:   3988\n" +
                    "TracerPid:      0\n" +
                    "Uid:    10165   10165   10165   10165\n" +
                    "Gid:    10165   10165   10165   10165\n" +
                    "FDSize: 512\n" +
                    "Groups: 3002 3003 9997 50165\n" +
                    "VmPeak:  2750476 kB\n" +
                    "VmSize:  2669768 kB\n" +
                    "VmLck:         0 kB\n" +
                    "VmPin:         0 kB\n" +
                    "VmHWM:    625440 kB\n" +
                    "VmRSS:    551996 kB\n" +
                    "VmData:   635512 kB\n" +
                    "VmStk:      8196 kB\n" +
                    "VmExe:        48 kB\n" +
                    "VmLib:    231276 kB\n" +
                    "VmPTE:      3056 kB\n" +
                    "VmSwap:    16756 kB\n" +
                    "Threads:        177\n" +
                    "SigQ:   6/9061\n" +
                    "SigPnd: 0000000000000000\n" +
                    "ShdPnd: 0000000000000000\n" +
                    "SigBlk: 0000000000001204\n" +
                    "SigIgn: 0000000000000000\n" +
                    "SigCgt: 00000002400096f8\n" +
                    "CapInh: 0000000000000000\n" +
                    "CapPrm: 0000000000000000\n" +
                    "CapEff: 0000000000000000\n" +
                    "CapBnd: 0000000000000000\n" +
                    "Seccomp:        0\n" +
                    "Cpus_allowed:   7f\n" +
                    "Cpus_allowed_list:      0-6\n" +
                    "Mems_allowed:   1\n" +
                    "Mems_allowed_list:      0\n" +
                    "voluntary_ctxt_switches:        1233861\n" +
                    "nonvoluntary_ctxt_switches:     323282").getBytes()));
        } else if ("/storage/emulated/0/sg_data".equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, "".getBytes()));
        } else if ("/dev/__properties__".equals(pathname)) {
            return FileResult.failed(-1);
        } else if ("/proc/stat".equals(pathname)) {
            String cpustat = "cpu  9595452 18805634 9206202 31897447 33297 872414 529261 0 0 0\n" +
                    "cpu0 1041666 6860538 1798101 30938055 22029 297994 209810 0 0 0\n" +
                    "cpu1 651798 9318879 2101410 6448 39 186389 85333 0 0 0\n" +
                    "cpu2 241133 1034733 198525 177580 35 55925 37225 0 0 0\n" +
                    "cpu3 156744 1357335 147862 177124 157 43996 39571 0 0 0\n" +
                    "cpu4 1799651 36371 1147765 153751 3297 87047 49413 0 0 0\n" +
                    "cpu5 2245936 36766 1372915 148107 2950 73580 36374 0 0 0\n" +
                    "cpu6 1874717 82971 1292947 146088 2430 64295 29611 0 0 0\n" +
                    "cpu7 1583803 78035 1146672 150290 2356 63183 41919 0 0 0\n" +
                    "intr 754681341 0 0 0 181129566 0 29963334 4 3 4 0 0 32 0 0 0 0 830116 0 0 12 0 0 0 0 0 0 0 0 0 0 1548 640 11 11 150957 0 0 0 0 0 0 0 3 60 0 89869 120479 2310144 22780630 0 5112713 0 0 13 0 0 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 487310 12 1420759 3178952 45173 0 0 0 0 0 1419511 39 5779547 0 0 0 0 82 953647 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2 0 2 0 0 2 0 6 6 7413 0 0 238 0 1 2415101 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2429 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4436 0 0 0 0 1 198 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 3 0 13 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4728947 11565 140 34703 24894 2038458 531 40302 86 38 0 0 0 0 561 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 169828 162930 4408 0 1 3259 0 0 0 0 0 0 0 0 0 2 0 0 0 2 19 19 0 24 17 48 49 0 0 0 0 0 0 0 0 0 0 81 0 0 0 104 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 595575 0 45 0 15 157 0 0 2 30 0 0 0 0 132 493792 2 0 12 101 13612 0 0 0 0 0 0 0 0 0 0 10973 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n" +
                    "ctxt 1000839366\n" +
                    "btime 1635775723\n" +
                    "processes 444076\n" +
                    "procs_running 3\n" +
                    "procs_blocked 0\n" +
                    "softirq 348812388 25269653 145488298 170737 5276360 4112838 39872 9044127 63500389 0 95910114";
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, cpustat.getBytes()));
        }
        else if ("/storage/emulated/0/fcd70f3c7711c0988bd8b9cdccf75794".equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                    "01c974b264b00233d60035030be1beea0f2847965ea6bbf337b48788087d23ec"
                            .getBytes()));
        }
        System.err.println("uncovered file");
        return null;
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        System.out.println("== callStaticObjectMethod_signature: " + signature);
        switch (signature) {
            case "android/os/Environment->getExternalStorageDirectory()Ljava/io/File;":
                return new StringObject(vm, "/storage/emulated/0");
            case "java/lang/String->getPath()Ljava/lang/String;":
                return new StringObject(vm, "./");
            case "okio/zz->b(I)Ljava/lang/String;":{
                int key = varArg.getIntArg(0);
                switch (key){
                    case 1:{
                        return new StringObject(vm, "353626076466627");
                    }
                    case 0:{
                        return new StringObject(vm, "8cff8823cf19b5ec");
                    }
                    case 101:{
                        return new StringObject(vm, "25483");
                    }
                    case 103:{
                        return new StringObject(vm, "1920*1080");
                    }
                    case 104:{
                        return new StringObject(vm, "");
                    }
                    case 102:{
                        return new StringObject(vm, "17637");
                    }
                    case 105:{
                        return new StringObject(vm, "WIFI");
                    }
                    case 106:{
                        return new StringObject(vm, "0.0.0.0:0");
                    }
                    case 8:{
                        return new StringObject(vm, "0.0.0.0:0");
                    }
                    case 9:{
                        return new StringObject(vm, "");
                    }
                    case 10:{
                        return new StringObject(vm, "00:00:00:00:00:00");
                    }
                    case 107:{
                        return new StringObject(vm, "[full-100]");
                    }
                    case 108:{
                        return new StringObject(vm, "78");
                    }
                    case 109:{
                        return new StringObject(vm, "");
                    }
                }
                System.out.println("okio/zz->b(I) Key:"+key);
            }
            case "java/net/NetworkInterface->getByName(Ljava/lang/String;)Ljava/net/NetworkInterface;":{
                String name = null;
                DvmObject<?> namedvm = varArg.getObjectArg(0);
                if(namedvm!=null){
                    name = (String) namedvm.getValue();
                }
                return vm.resolveClass("java/net/NetworkInterface").newObject(name);
            }
            default:
                break;
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        System.out.println("== callStaticObjectMethodV_signature: " + signature);
        switch (signature) {
            case "ctrip/android/sephone/apiutils/jazz/Utils->getUUIDForSession()Ljava/lang/String;":
            case "ctrip/android/sephone/apiutils/jazz/Utils->getUUIDForInstallation()Ljava/lang/String;":
            case "ctrip/android/sephone/apiutils/jazz/Utils->getUUIDForVendor()Ljava/lang/String;":
            case "ctrip/android/sephone/apiutils/jazz/Utils->getUUIDForDevice()Ljava/lang/String;":
            case "ctrip/android/sephone/apiutils/jazz/Utils->getSystemPhotoUUID()Ljava/lang/String;":
                return new StringObject(vm, UUID.randomUUID().toString());
            case "ctrip/android/sephone/apiutils/jazz/Utils->getAppInstallPath()Ljava/lang/String;":
                return new StringObject(vm, "/data/app/ctrip.android.view-wJDp0M39AEaR9jtNsffWZg==/base.apk");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getFirstInstallTime()Ljava/lang/String;":
            case "ctrip/android/sephone/apiutils/jazz/Utils->getLastUpdateTime()Ljava/lang/String;":
            case "ctrip/android/sephone/apiutils/jazz/Utils->getFirstUseTime()Ljava/lang/String;":
                return new StringObject(vm, String.valueOf(System.currentTimeMillis()));
            case "ctrip/android/sephone/apiutils/jazz/Utils->getBundleName()Ljava/lang/String;":
                return new StringObject(vm, "ctrip.android.view");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getAppVersion()Ljava/lang/String;":
                return new StringObject(vm, "8.35.3");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getAppVersionCode()Ljava/lang/String;":
                return new StringObject(vm, "1512");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getHostName()Ljava/lang/String;":
                return new StringObject(vm, "autosec-Precision-T1700");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getSystemVersion()Ljava/lang/String;":
                return new StringObject(vm, "8.1.0");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getkernelVersion()Ljava/lang/String;":
                return new StringObject(vm, "Linux version 4.4.88-g1df3f1db0988 (android-build@vpeb1.mtv.corp.google.com) (Android clang version 5.0.300080 (based on LLVM 5.0.300080)) #1 SMP PREEMPT Fri Mar 16 21:34:59 UTC 2018");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getNetNodeName()Ljava/lang/String;":
                return new StringObject(vm, "null");    // 蓝牙名字 BluetoothAdapter.getDefaultAdapter().name
            case "ctrip/android/sephone/apiutils/jazz/Utils->getOsName()Ljava/lang/String;":
                return new StringObject(vm, "Android"); // osName
            case "ctrip/android/sephone/apiutils/jazz/Utils->getMacAddress()Ljava/lang/String;":
                return new StringObject(vm, "EE:00:00:00:00:00");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getCpuStyle()Ljava/lang/String;":
                return new StringObject(vm, "arm64-v8a");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getRamSize()Ljava/lang/String;":
                return new StringObject(vm, "3823443968");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getCPUCores()Ljava/lang/String;":
                return new StringObject(vm, "8");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getActiveCpuCount()Ljava/lang/String;":
                return new StringObject(vm, "4");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getScreen()Ljava/lang/String;":
                return new StringObject(vm, "1440*2712");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getAppNativeDir()Ljava/lang/String;":
                return new StringObject(vm, "/data/app/ctrip.android.view-wJDp0M39AEaR9jtNsffWZg==/lib/arm64");
            case "ctrip/android/sephone/apiutils/jazz/Utils->getTimeZone()Ljava/lang/String;":
                return new StringObject(vm, "GMT");
            case "ctrip/android/sephone/api/Instance->getCurrentApplication()Landroid/app/Application;":
                return vm.resolveClass("android/app/Application", vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context"))).newObject(signature);
            case "android/app/Application->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return new ApplicationInfo(vm);
            default:
                return new StringObject(vm, "111");
        }
//        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        System.out.println("== callObjectMethod_signature: " + signature + ", val: " + dvmObject.getValue());
        switch (signature) {
            case "java/lang/String->getPath()Ljava/lang/String;":
                if ("java/lang/String".equals(dvmObject.getObjectType().getClassName())) {
                    return new StringObject(vm, dvmObject.getValue().toString());
                }
                return new StringObject(vm, "/storage/emulated/0");
            case "android/content/Context->getPackageResourcePath()Ljava/lang/String;":
                return new StringObject(vm, "/data/app/ctrip.android.view-0Bx31s-9Qvg8Aocjp8FsJQ==/base.apk");
            case "android/content/Context->getFilesDir()Ljava/io/File;":
                return new StringObject(vm, "/data/user/0/ctrip.android.view/files");
            case "android/content/Context->getAssets()Landroid/content/res/AssetManager;":
                return new AssetManager(vm, signature);
//                return new StringObject(vm, ".");
            case "java/net/NetworkInterface->getHardwareAddress()[B":
                byte[] result = hexStringToByteArray("64BC0C65AA1E");
                return new ByteArray(vm, result);
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        System.out.println("== callObjectMethodV_signature: " + signature + ", val: " + dvmObject.toString());
        switch (signature) {
            case "android/content/ContextWrapper->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return new ApplicationInfo(vm);
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        System.out.println("== getIntField_signature: " + signature + ", val: " + dvmObject.toString());
        switch (signature) {
            case "android/content/pm/ApplicationInfo->flags:I":
                return 0;
        }
        return super.getIntField(vm, dvmObject, signature);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        System.out.println("== getIntField_signature: " + signature + ", val: " + dvmClass.toString());
        switch (signature) {
            case "android/content/pm/ApplicationInfo->FLAG_DEBUGGABLE:I":
                return 0;
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        System.out.println("== getStaticObjectField: " + signature + ", val: " + dvmClass.toString());
        switch (signature) {
            default:
                return new StringObject(vm, "233333");
        }
    }
}