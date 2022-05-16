#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4 ft=python
import sys,os,getopt,re,string,yaml,json

class VaultPolicyGenerator(object):
    MODE_MAP = {
        'c': 'create',
        'r': 'read',
        'u': 'update',
        'd': 'delete',
        'l': 'list',
        's': 'sudo',
        'x': 'deny'
    }

    def getSubPathes(self, ppath: str, mode: str):
        spathes = {}
        spathes[ppath] = {'capabilities': self.parseCap(mode)}
        ppathSplit = ppath.rsplit('/')
        for i in range(len(ppathSplit) - 1):
            spathes['/'.join(ppathSplit[0:i+1])] = {
                'capabilities': self.parseCap(mode)
            }
        return spathes

    def parsePath(self, path: dict):
        vpathes = {}
        vcap = []
        ppath = path['path']
        mode  = path['capabilities']
        vpathes[ppath] = {'capabilities': self.parseCap(mode)}
        for m in self.MODE_MAP.keys():
            if m.upper() in mode:
                for spath, scap in self.getSubPathes(ppath, m).items():
                    if spath in vpathes:
                        vcaps = {'capabilities': vpathes[spath]['capabilities'] + self.parseCap(m)}
                    else:
                        vcaps = {'capabilities': self.parseCap(m)}
                    vpathes[spath] = vcaps
        return vpathes

    def parseCap(self, mode):
        caps = []
        for m, cap in self.MODE_MAP.items():
            if m in mode:
                caps.append(cap)
        return caps

    def merge_two_dicts(self, x, y):
        z = x.copy()   # start with x's keys and values
        z.update(y)    # modifies z with y's keys and values & returns None
        return z

    def parsePolicy(self, text: str):
        vpol   = {}
        policy = yaml.safe_load(text)
        if policy['path']:
            vpolPath = {}
            for path in policy['path']:
                pathes   = self.parsePath(path)
                vpolPath = self.merge_two_dicts(vpolPath, pathes)
            vpol['path'] = vpolPath
        self.viewPolicy(vpol)

    def viewPolicy(self, vpol):
        print(json.dumps(vpol, indent=2, sort_keys=True, ensure_ascii=False))

########################################################################
#                        Console
########################################################################

# settings
verbose = False

# usage
def usage(status = 0):
  global verbose
  print("Usage: \ncat policy.yaml | " + os.path.basename(sys.argv[0]))
  sys.exit(status)

# main
def main():
    global verbose,params
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hv",
            ["help", "verbose"]
        )
    except getopt.GetoptError as err:
        # print help information and exit:
        print(str(err)) # will print something like "option -a not recognized"
        usage(2)
    verbose = False
    for o, a in opts:
        if o == "-v":
            verbose = True
        elif o in ("-h", "--help"):
            usage()
        else:
            assert False, "unhandled option"
            usage()
    vaultPG = VaultPolicyGenerator()
    vaultPG.parsePolicy(sys.stdin)

if __name__ == "__main__":
    main()
