Working solution for client data visualization.

Note: Only works on firefox, because of stricter CRSF prevention protocols on other browsers.

Requires:
    - .txt file in the same directory with the name sensorData.txt that has the most up to date data for each pi in comma separated format.
        - Sample input for 3 sensors:
            datapoint1,datapoint2,datapoint3


How to update to contain datapoints for more than current version with only two devices
        Steps:
        - Copy line 30 after it to create a new datapoints array
            $ dpsn = [];
        - Create a corresponding line on the chart chartContainer (around line 48) by adding a JSON object tha looks like:
            $ {
                type: "line",
                dataPoints: dpsn //your corresponding datapoints array
            }
        - Line 53: add another "yValn = 0"; , to hold the data for extra device
        - Line 67: add another "yValn = parseFloat(nums[n]);" , to use the nth input from the file
        - Line 75: add another call to push the updated data to the dpsn array
            $ dpsn.push({
                x: xVal,
                y: yValn
            });
        - Line 85: add another check to ensure that only the set number of datapoints is visible on the screen at any point in time
            if (dpsn.length > dataLength) {
                dpsn.shift();
            }
        - That's it. You're done!
