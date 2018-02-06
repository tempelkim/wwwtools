from .utility import tex_esc


class Link:

    def __init__(self, url, label):
        self.url = url
        self.label = label

    def geturl(self):
        return self.url.geturl()

    def ltx_label(self):
        return tex_esc(self.label)
