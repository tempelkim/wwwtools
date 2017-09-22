class Domain(object):

    def __init__(self, domain):
        while domain.startswith('.'):
            domain = domain[1:]
        self.domain = domain.lower()
        self.domarr = self.domain.split('.')
        self.domarr.reverse()

    @property
    def tld(self):
        rv = ''
        depth = 1
        if self.domarr[0] == 'uk' and self.domarr[1] == 'co':
            depth = 2
        first = True
        while depth >= 0:
            if not first:
                rv += '.'
            rv += self.domarr[depth]
            first = False
            depth -= 1
        return rv

    def __str__(self):
        return self.domain

    def __eq__(self, other):
        return self.domain == other.domain

    def __lt__(self, other):
        i = 0
        if self.domarr[i] < other.domarr[i]:
            return True
        elif other.domarr[i] < self.domarr[i]:
            return False
        while True:
            i += 1
            if len(self.domarr) == i:
                if len(other.domarr) > i:
                    return True
                return False
            if len(other.domarr) == i:
                return False
            if self.domarr[i] < other.domarr[i]:
                return True
            elif self.domarr[i] > other.domarr[i]:
                return False
