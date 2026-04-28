 # Access Review Tool

  Automates periodic user access reviews by flagging stale accounts and admin   
  users for follow-up.
                                                                                
  ## What It Does 

  - Loads user records from a CSV file
  - Flags accounts with no login activity in the past 90 days
  - Escalates admin accounts and those missing a manager assignment             
  - Outputs a dated report CSV ready for auditor review                         
                                                                                
  ## Folder Structure                                                           
                                                                                
  grc-automation-toolkit/tools/access-review/
  ├── access_review.py       # Main script
  ├── user_access.csv        # Input: user roster (not committed — contains PII)
  └── README.md                                                                 
                                                                                
  ## How to Run                                                                 
                                                                                
  ```bash         
  python access_review.py

  Output: access_review_report_YYYYMMDD.csv in the same folder.                 
   
  Input Format                                                                  
                  
  user_access.csv must have these columns:

  ┌──────────────┬─────────────────────────┐
  │    Column    │       Description       │
  ├──────────────┼─────────────────────────┤                                    
  │ username     │ Unique user ID          │
  ├──────────────┼─────────────────────────┤                                    
  │ full_name    │ Display name            │
  ├──────────────┼─────────────────────────┤
  │ department   │ Team or department      │
  ├──────────────┼─────────────────────────┤
  │ role         │ Job title               │
  ├──────────────┼─────────────────────────┤
  │ access_level │ admin or standard       │
  ├──────────────┼─────────────────────────┤                                    
  │ last_login   │ ISO date (YYYY-MM-DD)   │
  ├──────────────┼─────────────────────────┤                                    
  │ manager      │ Manager name (optional) │
  └──────────────┴─────────────────────────┘                                    
   
  Compliance Use Case                                                           
                  
  Supports periodic access review controls under frameworks like SOC 2 (CC6.2), 
  ISO 27001 (A.9), and NIST 800-53 (AC-2).

