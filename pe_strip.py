import pefile
import sys
import time
import ntpath


def clean_timestamp(pe):

    print '# Cleaning timestamp'

    def formatter(ts):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))

    before = formatter(pe.FILE_HEADER.TimeDateStamp)
    pe.FILE_HEADER.TimeDateStamp = 0
    after = formatter(pe.FILE_HEADER.TimeDateStamp)

    print '{} -> {}'.format(before, after)


def clean_debug_if_exists(pe):

    print '# Cleaning debug unfo'
    if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        return

    for d in pe.DIRECTORY_ENTRY_DEBUG:
        try:
            path_before = d.entry.PdbFileName
            d.entry.PdbFileName = ntpath.basename(path_before)
            path_after = d.entry.PdbFileName

            age_before = d.entry.Age
            d.entry.Age = 1
            age_after = d.entry.Age

            print '# # PDB path: {} -> {}'.format(path_before, path_after)
            print '# # Age: {} -> {}'.format(age_before, age_after)
        except:
            pass


def fix_checksum_if_exists(pe):

    print '# Fixing checksum'
    if pe.OPTIONAL_HEADER.CheckSum:
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()


def save_output(pe, out_path):

    print '# Writing cleaned PE to {}'.format(out_path)
    pe.write(filename=out_path)


def usage():
    print '{} <pe.exe>'.format(sys.argv[0])


def main():

    try:
        _, pe_path = sys.argv
    except:
        usage()
        return

    pe = pefile.PE(pe_path)

    clean_timestamp(pe)
    clean_debug_if_exists(pe)
    fix_checksum_if_exists(pe)

    out_path = pe_path + '.clean.exe'
    save_output(pe, out_path)

main()
