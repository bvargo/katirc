# -*- coding: utf-8 -*-

import unicodedata

# strips accents from characters, producing valid ASCII text
# for example, ü becomes u, á becomes a, ķ becomes k, etc
def strip_accents(s):
   return ''.join(c for c in unicodedata.normalize('NFD', s)
           if unicodedata.category(c) != 'Mn')
