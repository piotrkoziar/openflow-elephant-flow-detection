

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

    def _import_base_path(self):
        # use this method to import base path to the PathManager module, e.g. from config file
        path1 = Path(1, 1, 3) # s1 <-> s3
        path1.append(2, 1, 3) # s2 <-> h2

        self.base_path = path1

    def _import_alt_paths(self):
        # use this method to import alt paths to the PathManager module, e.g. from config file
        path1 = Path(1, 1, 4) # s1 <-> s4
        path1.append(2, 1, 4) # s2 <-> h2

        self.alt_paths.append(path1)

        path1 = Path(1, 1, 5) # s1 <-> s5
        path1.append(2, 1, 5) # s2 <-> h2

        self.alt_paths.append(path1)

        self.alt_number = 2

    def __init__(self):
        self.base_path = Path()
        self.alt_paths = []
        self.alt_number = 0

        self._import_base_path()
        self._import_base_path()

        self._path_variant = 0


    def get_base_path(self):
        return self.base_path


    def get_alt_path(self):
        if self.alt_number <= 0:
            return None

        idx = self._path_variant

        self._path_variant = (self._path_variant + 1) % self.alt_number

        return self.alt_paths[idx]