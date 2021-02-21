

class Path():
    def __init__(self, dpid = 0, port1 = 0, port2 = 0):
        self._port_pairs = {}
        if port1 * port2 > 0:
            self._port_pairs[dpid] = ( port1, port2 )

    def __getitem__(self, key):
        if key in self._port_pairs.keys():
            return self._port_pairs[key]
        else:
            return ( None, None )

    def append(self, dpid, port1, port2):
        self._port_pairs[dpid] = ( port1, port2 )

    def get_length(self):
        return len(self._port_pairs.keys())

class PathManager():

    def _import_paths(self):
        # use this method to import paths to the PathManager module, e.g. from config file

        # base1
        path_base = Path(1, 1, 3) # s1 <-> s3
        path_base.append(2, 1, 3) # s2 <-> h2
        self.alt_paths[path_base] = []

        # alt1(base1)
        path = Path(1, 1, 4) # s1 <-> s4
        path.append(2, 1, 4) # s2 <-> h2
        self.alt_paths[path_base].append(path)

        # alt2(base1)
        path = Path(1, 1, 5) # s1 <-> s5
        path.append(2, 1, 5) # s2 <-> h2
        self.alt_paths[path_base].append(path)


    def __init__(self):
        self._path_variant = {}
        self.alt_paths = {}

        self._import_paths()

        self.dpid_to_increment = {}

    def get_base_paths(self):
        return self.alt_paths.keys()

    def get_alt_path(self, dpid, base_path):

        try:
            n_of_alt_paths = len(self.alt_paths[base_path])
        except KeyError:
            return None

        self.dpid_to_increment.setdefault(dpid, -1)
        self.dpid_to_increment[dpid] = (self.dpid_to_increment[dpid] + 1) % n_of_alt_paths

        idx = self.dpid_to_increment[dpid]

        return self.alt_paths[base_path][idx]

path_manager = PathManager()

