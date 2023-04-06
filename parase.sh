#!/bin/bash

path_input=./packet
path_output=./result

if [ ! -d $path_output ];then
  mkdir $path_output
fi

files=$(ls $path_input)
for filename in $files
do
 ./pcapparase $path_input"/"${filename%.*}".pcap" > $path_output"/"${filename%.*}".txt"
done
echo $path_input": 解析结束"
