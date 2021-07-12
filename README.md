#challenge

1) The report will have 8 items:

    a. The total number of server requests within the log file (all internal/external ips)
    
    b. Number of requests after removing all the entries where you have application ports: 80 and 443
    
    c. All the requests from external IPs (public company IPs also excluded)
    
    d. Number of unique IPs within the external requests list
    
    e. All the accepted and rejected requests (after the above filters to be applied)
    
    f. Unauthorized SSH accesses
    
    g. List of IPs and the number of requests made by each one
    
    h. All ports target of requests and the number of requests made over each one
    
    The final_report.txt will be generated in the same location you run the main script

2) What you need to execute the script:

    Please make sure you have installed Python 3.9.x

    Requirements file generated with "pip freeze > requirements.txt"

    Command to install the requirements >> pip install -r requirements.txt

    Put the log.txt file in the same folder where you have the main.py script

    Script execution: from a terminal please run >> Python main.py 
