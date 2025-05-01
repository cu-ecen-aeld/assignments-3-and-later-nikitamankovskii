#!/bin/sh
 
if [ "$#" -ne 2 ]; 
then
    echo "Usage: finder.sh filesdir searchstr"
    exit 1
fi

filesdir=$1
searchstr=$2

if [ -d $filesdir ]; 
then 
    x=$(find $filesdir -type f | wc -l)
    y=$(grep -Rl $searchstr $filesdir | wc -l)
    echo "The number of files are $x and the number of matching lines are $y"
else
    echo "Error. '$filesfir' not exit."
    exit 1
fi