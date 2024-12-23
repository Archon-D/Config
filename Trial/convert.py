import yaml

def generate_ruleprovider(ruleset):
    # 创建一个空字典来存储生成的结果
    output_dict = {}
    # 遍历 ruleset 中的每一项
    for rule in ruleset
        # 获取标签（tag）和 URL
        tag = rule.get("tag")
        url = rule.get("url")
        if tag and url:
            # 根据标签生成对应的域名规则，例如 netflix_domain
            domain_key = f"{tag}"
            # 构造输出的结构
            output_dict[domain_key] = {
                "<<": "*domain",  # 表示继承定义的 domain
                "url": url        # URL 地址
            }
    # 使用 yaml 库生成格式化的 YAML 字符串
    yaml_output = yaml.dump(output_dict, default_flow_style=False, allow_unicode=True) 
    return yaml_output


def format_rules(input_list):
    output = []
    
    # 遍历输入数组
    for entry in input_list:
        rule_set = entry.get("rule_set")
        outbound = entry.get("outbound")
        
        # 格式化并加入输出列表
        output.append(f"- RULE-SET,{rule_set},{outbound}")
    
    return "\n".join(output)

def format_proxy(input_list):
    # 映射规则
    type_mapping = {
        "selector": "select",
        "urltest": "url-test"
    }
    
    output = []
    
    # 遍历输入数组
    for entry in input_list:
        tag = entry.get("tag")
        type_ = entry.get("type")    
        # 映射 type 值
        mapped_type = type_mapping.get(type_, type_)  # 默认保持原样
        
        if "outbounds" in entry:  # 处理包含 outbounds 字段的情况
            outbounds = entry.get("outbounds", [])
            proxies = f"[{', '.join(outbounds)}]" if outbounds else "[]"
            output.append(f"- name: {tag}\n    type: {mapped_type}\n    proxies: {proxies}")
        
        elif "regex" in entry:  # 处理包含 regex 字段的情况
            regex = entry.get("regex", "")
            filter_ = f'“{regex}”' if regex else '“”'
            output.append(f"- name: {tag}\n    type: {mapped_type}\n    include-all: true\n    filter: {filter_}")
    
    return "\n\n".join(output)
