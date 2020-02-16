#! /usr/bin/env python
import download
import argparse
import sys
import json

malshare = "https://malshare.com/"


def get_file_list(apikey, filetype="PE32"):
    target_url = "{}/api.php?api_key={}&action=type&type={}".format(malshare, apikey, filetype)
    download.download(target_url, "/tmp/filelist", kind='file', progressbar=True, replace=True,timeout=600)
    with open("/tmp/filelist", 'rb') as f:
        filelist = json.load(f, )
    return list(map(lambda x:x['md5'],filelist))


def download_malware(apikey, filetype="PE", timeout=300, outdir='.'):
    # step 1: get file list from malshare.com
    filelist = get_file_list(apikey, filetype)
    filelist_file = "{}/{}".format(outdir,"filelist")
    faillist_file = "{}/{}".format(outdir,'faillist')
    with open(faillist_file,'r') as f:
        faillist = set(list(map(lambda x:x.strip(),f.readlines())))
    with open(filelist_file,'r') as f:
        oldfiles = set(list(map(lambda x:x.strip(),f.readlines())))
        filelist = (set(filelist) - oldfiles) | faillist
    itr = 0
    while len(filelist) != 0:
        faillist = set()
        for file in filelist:
            target_url = "{}/api.php?api_key={}&action=getfile&&hash={}".format(malshare,
                                                                                 apikey,
                                                                                 file)
            try:
                download.download(target_url,"{}/{}".format(outdir,file),
                                  replace=True,progressbar=True,
                                  timeout=timeout)
            except:
                faillist.add(file)
                continue
            oldfiles.add(file)
        itr += 1
        filelist = faillist
        if itr == 5:
            break
    with open(filelist_file,'w') as f:
        f.write(" ".join(list(oldfiles)))

    with open(faillist_file,'w') as f:
        f.write(" ".join(list(faillist)))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-k',"--apikey", required=True, help="Your API key for malshare.", type=str)
    parser.add_argument('-t',"--timeout", required=False, default=300, type=int, help="Longest time for downloading files.")
    parser.add_argument('-f',"--filetype", required=False, default="PE32", type=str, help="File type to download.",
                        choices=['PE32',"PE32+",])
    parser.add_argument('-o',"--outdir", required=False, default='.', type=str, help="Directory to save files.")
    args = parser.parse_args(sys.argv[1:])
    download_malware(args.apikey, args.filetype, args.timeout, args.outdir)


if __name__ == '__main__':
    main()
