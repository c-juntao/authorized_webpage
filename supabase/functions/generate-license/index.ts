import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import forge from "https://esm.sh/node-forge@1.3.1"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
  // 1. 处理跨域 OPTIONS 请求 (如果不小心删了这行，就会报你截图里的 CORS 错误)
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })

  try {
    const { activation_code, machine_uuid } = await req.json()

    if (!activation_code || !machine_uuid) {
        return new Response(JSON.stringify({ error: "激活码和机器码不能为空" }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 })
    }

    // 2. 初始化 Supabase 客户端 (使用 Service Role Key)
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    )

    // 3. 验证激活码
    const { data: licenseData, error } = await supabaseClient
      .from('user_licenses')
      .select('*')
      .eq('activation_code', activation_code)
      .single()

    if (error || !licenseData || !licenseData.is_active) {
      return new Response(JSON.stringify({ error: "激活码无效或已被封禁" }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 400 })
    }

    // ================= 核心防滥用漏洞修补 & 一次性特权券机制 =================
    let shouldUpdateLastBoundTime = false;
    let isDeviceChanged = false; 

    if (licenseData.machine_uuid) {
        if (licenseData.machine_uuid !== machine_uuid) {
            const lastBoundDate = new Date(licenseData.last_bound_time);
            const cooldownDays = licenseData.cooldown_days ?? 180; 
            
            const availableDate = new Date(lastBoundDate.getTime() + cooldownDays * 24 * 60 * 60 * 1000);
            const now = new Date();

            if (now < availableDate) {
                const dateStr = availableDate.toISOString().split('T')[0];
                return new Response(JSON.stringify({ 
                    error: `拒绝签发！防滥用限制：距离上次绑定需满 ${cooldownDays} 天。下次可用换绑日期为：${dateStr}。` 
                }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 403 })
            }
            
            shouldUpdateLastBoundTime = true;
            isDeviceChanged = true; 
        }
    } else {
        shouldUpdateLastBoundTime = true;
        isDeviceChanged = true;
    }
    // ======================================================

    // 4. 更新数据库中的机器码状态
    const updatePayload: any = { machine_uuid: machine_uuid };
    
    if (shouldUpdateLastBoundTime) {
        updatePayload.last_bound_time = new Date().toISOString();
    }
    if (isDeviceChanged) {
        updatePayload.cooldown_days = 180;
    }

    await supabaseClient
      .from('user_licenses')
      .update(updatePayload)
      .eq('activation_code', activation_code)

    // 5. 读取私钥
    const privateKeyPem = Deno.env.get('RSA_PRIVATE_KEY') || ''
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem)

    // 6. 组装授权数据并转化为字符串 (这串文本就是签名的唯一真理)
    const payload = {
      activation_code,
      machine_uuid,
      product_name: licenseData.product_name,
      expire_time: licenseData.expire_time
    }
    const payloadStr = JSON.stringify(payload)
    
    // 使用这个字符串生成签名
    const md = forge.md.sha256.create()
    md.update(payloadStr, 'utf8')
    const signatureBytes = privateKey.sign(md)
    const signatureB64 = forge.util.encode64(signatureBytes)

    // 7. 返回带 raw_data 的最终 License
    const finalLicense = { 
        raw_data: payloadStr,        // 新增：未被二次解析的原始字符串
        data: payload,               // 留给前端展示用
        signature: signatureB64 
    }

    return new Response(JSON.stringify(finalLicense), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 200,
    })

  } catch (err) {
    // 捕获所有代码运行期错误，防止网关崩溃抛出 503
    return new Response(JSON.stringify({ error: err.message }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' }, status: 500 })
  }
})