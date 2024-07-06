from collections import deque


def find_intra_paths(G, entry, invalid_bbs) :
    que = deque([entry])
    prev = {}
    while len(que) > 0 :
        curr = que.popleft()
        if curr not in G :
            continue

        for _next in G[curr] :
            if _next in invalid_bbs :
                continue
            if _next not in prev :
                que.append(_next)
                prev[_next] = curr
    return prev

def get_path_from_prev(src, dest, prev) :
    path = []
    curr = dest
    while True :
        path.append(curr)
        if curr == src : 
            break
        if curr not in prev :
            print(curr, src, dest)
        curr = prev[curr]
    path.reverse()
    return path

def find_intra_path(G, src, dest, reachable = None, CGEdge2caller = None) :
    prev = {}
    que = deque([src])
    prev[src] = src
    while len(que) > 0 :
        curr = que.popleft()
        if curr == dest :
            break
        if curr not in G :
            continue

        for next in G[curr] :
            if reachable is not None :
                flag = False
                for caller in CGEdge2caller[(curr, next)] :
                    if caller in reachable :
                        flag = True
                        break
                if flag == False :
                    continue
            if next not in prev :
                que.append(next)
                prev[next] = curr

    if dest not in prev :
        return None

    path = get_path_from_prev(src, dest, prev)
    return path

def find_inter_path(CFG, CG, caller2callee, block_distance, target, i2f, func_all) :
    CGEdge2caller = {}
    for caller, callees in caller2callee.items() :
        for callee in callees :
            if i2f[caller] not in func_all :
                continue
            caller_func = i2f[caller]
            callee_func = i2f[callee]
            edge = (caller_func, callee_func)
            if edge not in CGEdge2caller :
                # need to be set since caller may call callee many times in different position
                CGEdge2caller[edge] = set() 
            CGEdge2caller[edge].add(caller)
    src_bb, dest_bb = target
    src_func = i2f[src_bb]
    dest_func = i2f[dest_bb]
    call_path = find_intra_path(CG, src_func, dest_func, block_distance[src_bb], CGEdge2caller)
    path = []
    tmp_path = None

    if len(call_path) == 1 :
        path = find_intra_path(CFG, src_bb, dest_bb)
    else :
        # print(CGEdge2caller.keys())
        for i in range(0, len(call_path) - 1) :
            edge = (call_path[i], call_path[i + 1])
            for dest_tmp in CGEdge2caller[edge] :
                if i == 0 :
                    tmp_path = find_intra_path(CFG, src_bb, dest_tmp)
                else :
                    tmp_path = find_intra_path(CFG, call_path[i], dest_tmp)
                if tmp_path is None :
                    print(call_path)
                    print(src_bb, dest_bb, dest_tmp, call_path[i], call_path[i+1], i )
                if tmp_path is not None :
                    break
            assert(tmp_path is not None)
            path += tmp_path

        path += find_intra_path(CFG, call_path[-1], dest_bb)

    return path
