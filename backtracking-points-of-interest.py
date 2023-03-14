import pygraphviz as pgv
from ast import literal_eval
# Getting log files using sysdig 
# To get tcp, udp events - sudo sysdig -p "%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency exepath=%proc.exepath proc_pid =%proc.pid file_id=%fd.num  fd_name=%fd.name  fd_cip=%fd.cip fd_sip=%fd.sip fd_lip=%fd.lip fd_rip=%fd.rip fd_cport=%fd.cport fd_sport=%fd.sport fd_lport=%fd.lport fd_rport=%fd.rport fd_l4protocol= %fd.l4proto " "proc.name!=tmux and (evt.type=read or evt.type=readv or evt.type=write or evt.type=writev or evt.type=accept or evt.type=execve or evt.type=clone or evt.type=pipe or evt.type=rename or evt.type=sendmsg or evt.type=recvmsg)" and proc.name!=sysdig > sysdig_28_11_2022_3_4_1.txt
# To get file access events - sudo sysdig -p "%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency exepath=%proc.exepath proc_pid =%proc.pid file_id=%fd.num  fd_name=%fd.name  fd_filename=%fd.filename" "proc.name!=tmux and (evt.type=read or evt.type=readv or evt.type=write or evt.type=writev or evt.type=accept or evt.type=execve or evt.type=clone or evt.type=pipe or evt.type=rename or evt.type=sendmsg or evt.type=recvmsg)" and proc.name!=sysdig > sysdig_28_11_2022_3_4_2.txt
def parse_sysdig_events(filePath):
    logsList = []
    parsedLogTuples = []
    with open(filePath) as logsFile:
        for line in logsFile:
            logsList.append(line)
    for log in logsList:
        processName = log.split()[3]
        pID = log.split('proc_pid =', 1)[1].split()[0]
        processType = log.split()[6]
        fileID = log.split('file_id=', 1)[1].split()[0]
        eventType = log.split()[5]
        fdCIP, fdSIP, fdCPort, fdSPort, fdL4Protocol, fdFileName, parsedLogTuple = None, None, None, None, None, None, None
        if 'fd_cip' in log:
            fdCIP = log.split('fd_cip=', 1)[1].split()[0]
            fdSIP = log.split('fd_sip=', 1)[1].split()[0]
            fdCPort = log.split('fd_cport=', 1)[1].split()[0][1:]
            fdSPort = log.split('fd_sport=', 1)[1].split()[0][1:]
            fdL4Protocol = log.split('fd_l4protocol= ', 1)[1].split()[0]
        else:
            fdFileName = log.split('fd_filename=', 1)[1].split()[0]
        # Tuple structure:
        # for tcp/udp connections - ((processID, processName), (processType, eventType), (fileID, file client IP, file server IP, file client port, file server port, file access protocol))
        # for normal file access - ((processID, processName), (processType, eventType), (fileID, fileName))
        if fdCIP and fdSIP and fdCPort and fdSPort and fdL4Protocol:
            parsedLogTuple = ((pID, processName), (processType, eventType), (fileID, fdCIP, fdSIP, fdCPort, fdSPort, fdL4Protocol))
        else:
            parsedLogTuple = ((pID, processName), (processType, eventType), (fileID, fdFileName))
        parsedLogTuples.append(parsedLogTuple)
    print(parsedLogTuples)
    return parsedLogTuples
    
# graph edges -> file id 
# edge weights calculation - use the iterator value i - if < start time = i else if > end time = i, final edge weight -[start time, end time]
def create_graphs_from_tuples(logTuples):
    logsGraph = pgv.AGraph(directed=True, strict=True)
    logsGraph.node_attr["shape"] = "circle"
    for iterator, logTuple in enumerate(logTuples):
        # Since FS processes have no files associated
        if logTuple[0][1] == 'FS':
            continue
        node1 = str(logTuple[0][0]) + ' ' + str(logTuple[0][1])
        fileName = ''
        parentNode, childNode = '', ''
        if len(logTuple[2]) == 2:
            fileName = logTuple[2][1]
        node2 = str(logTuple[2][0]) + ' ' + fileName if len(fileName) > 0 else str(logTuple[2][0])
        # Event types (evt.type=read or evt.type=readv or evt.type=write or evt.type=writev or evt.type=accept or evt.type=execve or evt.type=clone or evt.type=pipe or evt.type=rename or evt.type=sendmsg or evt.type=recvmsg)
        if logTuple[1][0] in ['read', 'readv', 'execve', 'sendmsg', 'accept']:
            parentNode = node2
            childNode  = node1
        else:
            parentNode = node1
            childNode  = node2
        if logsGraph.has_edge(parentNode, childNode):
            edge = logsGraph.get_edge(parentNode, childNode)
            if edge.attr['label']:
                weight = literal_eval(edge.attr['label'])
                if len(weight) == 2 and logTuple[1][1] == '<':
                    weight.append(iterator)
                    edge.attr['label'] = weight
        else:
            logsGraph.add_node(parentNode)
            logsGraph.add_node(childNode)
            logsGraph.add_edge(parentNode, childNode)
            edge = logsGraph.get_edge(parentNode, childNode)
            if logTuple[1][1] == '>':
                edge.attr['label'] = [logTuple[1][0], iterator]
    logsGraph.layout(prog="dot")
    logsGraph.draw("logsTestGraph.svg")
    return logsGraph

# recursive function to backtrack and add nodes to the backtrack graph
def backtrack(parentNode, childNode, visited, maxEndTime, backtrackGraph, logsGraph):
    print(parentNode)
    edge = logsGraph.get_edge(parentNode, childNode)
    if edge in visited:
        return
    visited.add(edge)
    backtrackGraph.add_edge(parentNode, childNode)
    backtrackEdge = backtrackGraph.get_edge(parentNode, childNode)
    backtrackEdge.attr['label'] = edge.attr['label']
    if len(logsGraph.in_edges(parentNode)) == 0:
        return
    for incomingEdge in logsGraph.in_edges(parentNode):
        if  literal_eval(incomingEdge.attr['label'])[1] < int(maxEndTime):
            backtrack(logsGraph.get_node(incomingEdge[0]), parentNode, visited, maxEndTime, backtrackGraph, logsGraph)



# given parent node and child node find maxEndTime
# using in nodes for parent add all in nodes based on start time < end time to nodesToProcess
# add parent - child edge to backtrackGraph
# recursively find all the edges for nodes from  nodesToProcess to add to graph
# visited will track nodes visited to avoid processing node again in case of loops
def backtrackPointOfInterest(graphFilePath, parentNode, childNode, logsGraph):
    visited = set()
    maxEndTime = 0
    backtrackGraph = pgv.AGraph(directed=True, strict=True)
    
    if logsGraph.has_edge(parentNode, childNode):
        edge = logsGraph.get_edge(parentNode, childNode)
        weight = literal_eval(edge.attr['label'])
        maxEndTime = weight[2]
        backtrack(parentNode, childNode, visited, maxEndTime, backtrackGraph, logsGraph)
        backtrackGraph.layout(prog="dot")
        backtrackGraph.draw("BackTrackGraph.svg")
    else:
        print("Point of interest not present in the graph")


#parsedLogTuples = parse_sysdig_events('/home/diyabiju/sysdig_28_11_2022_3_4_1.txt')
parsedLogs = parse_sysdig_events('sysdig_1_12_2022_3_4_2rand.txt')
logsGraph = create_graphs_from_tuples(parsedLogs)
backtrackPointOfInterest('logsTestGraph.svg', '17840 sh', '1 shfile.sh', logsGraph)
