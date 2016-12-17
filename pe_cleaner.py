import pefile
import sys
import time
import ntpath


def clean_timestamp(pe):

    def formatter(ts):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))

    before = formatter(pe.FILE_HEADER.TimeDateStamp)
    pe.FILE_HEADER.TimeDateStamp = 0
    after = formatter(pe.FILE_HEADER.TimeDateStamp)

    print '{} -> {}'.format(before, after)


def clean_debug(pe):

    for d in pe.DIRECTORY_ENTRY_DEBUG:
        try:
            path_before = d.entry.PdbFileName
            d.entry.PdbFileName = ntpath.basename(path_before)
            path_after = d.entry.PdbFileName

            age_before = d.entry.Age
            d.entry.Age = 1
            age_after = d.entry.Age

            print 'PDB Path: {} -> {}'.format(path_before, path_after)
            print 'Age: {} -> {}'.format(age_before, age_after)
        except:
            pass


def usage():
    print '{} <pe.exe>'.format(sys.argv[0])


def main():

    try:
        _, pe_path = sys.argv
    except:
        usage()
        return

    pe = pefile.PE(pe_path)

    print '# Cleaning PE Timestamp'
    clean_timestamp(pe)

    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        print '# Cleaning Debug Info'
        clean_debug(pe)
    else:
        print '# There is no debug info to clean'

    out_path = pe_path + '.clean.exe'
    print '# Writing cleaned PE to {}'.format(out_path)
    pe.write(filename=out_path)

    print '# Done'


main()
