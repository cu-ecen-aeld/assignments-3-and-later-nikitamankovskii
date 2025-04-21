#!/usr/bin/bash
 
if [ "$#" -ne 2 ]; 
then
    echo "Usage: writer.sh writefile writestr"
    exit 1
fi

writefile=$1
writedir=$(dirname "$writefile")
#filename=$(basename "$writefile")
writestr=$2

if [ -d $writedir ]; 
then 
    echo 'File exist, overwritng.'
else
    mkdir -p "$writedir"
    if [[ $? -ne 0 ]]; 
    then
        echo "Failed to create '$writedir'."
        exit 1
    else
        echo "Created folder '$writedir'."
    fi
fi

echo $writestr > $writefile

if [[ $? -ne 0 ]]; 
then
    echo "Failed. writer.sh is not writer.sh'ing. Failed to write to '$writefile'."
    exit 1
else
    echo "Success. '$writestr' was written to '$writefile'."
fi