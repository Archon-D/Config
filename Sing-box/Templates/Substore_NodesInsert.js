const { type, name } = $arguments
const compatible_outbound = {
  tag: 'COMPATIBLE',
  type: 'direct',
}

let compatible
let config = JSON.parse($files[0])
let proxies = await produceArtifact({
  name: 'All',
  type: 'collection',///^1$|col/i.test(type) ? 'collection' : 'subscription',
  platform: 'sing-box',
  produceType: 'internal',
})

config.outbounds.push(...proxies)

config.outbounds.map(i => {
   if (['🇯🇵 日本HQ'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=HQ.*(?:日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan))(?!.*(?:港|美|韩|新|台|Game)).*$/))
  }
  if (['🇸🇬 狮城HQ'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=HQ.*(?:新加坡|坡|狮城|SG|Singapore))(?!.*(?:港|美|日|韩|台|Game)).*$/))
  }
  if (['🇺🇲 美国HQ'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=HQ.*(?:美|US|States|American))(?!.*(?:港|台|日|韩|新|Game)).*$/))
  }
  if (['SP|特殊节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?!.*(港|台|日本|韩|坡|美|HK|US|TW|JP|KR|SG|Hong|Tai|Japan|Korea|Singapore|States|Game)).*$/))
  }
  if (['🇰🇷 韩国节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=SN.*(?:KR|Korea|KOR|首尔|韩|韓))(?!.*(?:港|美|日|新|台|Game)).*$/))
  }
  if (['🇸🇬 狮城节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=SN.*(?:新加坡|坡|狮城|SG|Singapore))(?!.*(?:港|美|日|韩|台|Game)).*$/))
  }
  if (['🇨🇳 台湾节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=SN.*(?:台|新北|彰化|TW|Taiwan))(?!.*(?:港|美|日|韩|新|Game)).*$/))
  }
  if (['🇺🇲 美国节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=SN.*(?:美|US|States|American))(?!.*(?:港|台|日|韩|新|Game)).*$/))
  }
  if (['🇯🇵 日本节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=SN.*(?:日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan))(?!.*(?:港|美|韩|新|台|Game)).*$/))
  }
  if (['🇭🇰 香港节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=SN.*(?:港|HK|hk|Hong Kong|HongKong|hongkong))(?!.*(?:日本|美|韩|新|台|Game)).*$/))
  }
  if (['加密货币'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=.*(?:HQ))(?!.*(?:越|新|美|韩|泰|印度|马来)).*$/))
  }
  if (['经济节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^ECO.*$/))
  }
  if (['中间节点'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /^(?=.*(?:美|US|States|American))(?!.*(?:港|台|日|韩|新|Game)).*$/))
  }
  if (['Game'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies, /.*Game.*/))
  }
})

config.outbounds.forEach(outbound => {
  if (Array.isArray(outbound.outbounds) && outbound.outbounds.length === 0) {
    if (!compatible) {
      config.outbounds.push(compatible_outbound)
      compatible = true
    }
    outbound.outbounds.push(compatible_outbound.tag);
  }
});

$content = JSON.stringify(config, null, 2)

function getTags(proxies, regex) {
  return (regex ? proxies.filter(p => regex.test(p.tag)) : proxies).map(p => p.tag)
}
