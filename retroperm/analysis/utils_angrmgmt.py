import angr

def fast_memory_load_pointer(project, addr, size=None):
    try:
        return project.loader.memory.unpack_word(addr, size=size)
    except KeyError:
        return None

def is_printable(ch):
    return 32 <= ch < 127

def filter_string_for_display(s):
    output = ""
    for ch in s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t"):
        char = ord(ch)
        if not is_printable(char):
            ch = "\\x%0.2x" % char
        output += ch
    return output

def string_at_addr(cfg, addr, project, max_size=50):
    try:
        mem_data = cfg.memory_data[addr]
    except KeyError:
        return None

    if mem_data.sort == "string":
        str_content = mem_data.content.decode("utf-8")
    elif mem_data.sort == "pointer-array":
        ptr = fast_memory_load_pointer(project, mem_data.address)
        try:
            next_level = cfg.memory_data[ptr]
        except KeyError:
            return None

        if next_level.sort != "string":
            return None

        str_content = next_level.content.decode("utf-8")
    else:
        return None

    if str_content is not None:
        if len(str_content) > max_size:
            return '"' + filter_string_for_display(str_content[:max_size]) + '..."'
        else:
            return '"' + filter_string_for_display(str_content) + '"'
    else:
        return None