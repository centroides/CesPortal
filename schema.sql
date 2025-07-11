CREATE TABLE admin_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, -- email
    rate_per_hour INT,
    username TEXT NOT NULL,
    department_code INTEGER NOT NULL,
    register BOOLEAN NOT NULL DEFAULT '0',
    primary_role TEXT;
    secondary_role TEXT;
    secondary_role_code INTEGER;
    FOREIGN KEY (department_code) REFERENCES departments (department_code)
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT,
    password TEXT NOT NULL,
    admin BOOLEAN NOT NULL DEFAULT '0',
    department_code INTEGER,
    FOREIGN KEY (department_code) REFERENCES departments (department_code),
    FOREIGN KEY (id) REFERENCES admin_user (username),
);

CREATE TABLE access_control (
    Employee_ID TEXT PRIMARY KEY,   
    -- Accounts
    Accounts TEXT CHECK(Accounts IN ('On', 'Off')),  
    toggleClient TEXT CHECK(toggleClient IN ('On', 'Off')),  
    toggleAddClient TEXT CHECK(toggleAddClient IN ('On', 'Off')),  
    toggleEditClient TEXT CHECK(toggleEditClient IN ('On', 'Off')),  
    toggleDeleteClient TEXT CHECK(toggleDeleteClient IN ('On', 'Off')),  
    toggleSuppliers TEXT CHECK(toggleSuppliers IN ('On', 'Off')),  
    toggleAddSupplier TEXT CHECK(toggleAddSupplier IN ('On', 'Off')),  
    toggleEditSupplier TEXT CHECK(toggleEditSupplier IN ('On', 'Off')),  
    toggleDeleteSupplier TEXT CHECK(toggleDeleteSupplier IN ('On', 'Off')),  
    toggleExpenses TEXT CHECK(toggleExpenses IN ('On', 'Off')),  
    toggleInvoice TEXT CHECK(toggleInvoice IN ('On', 'Off')),  
    toggleNewInvoice TEXT CHECK(toggleNewInvoice IN ('On', 'Off')),  
    toggleEditInvoice TEXT CHECK(toggleEditInvoice IN ('On', 'Off')),  
    toggleDeleteInvoice TEXT CHECK(toggleDeleteInvoice IN ('On', 'Off')),  
    toggleViewInvoice TEXT CHECK(toggleViewInvoice IN ('On', 'Off')),  
    toggleOverHeadPayReq TEXT CHECK(toggleOverHeadPayReq IN ('On', 'Off')),  
    toggle_ac_overhead_pay_NewRequest TEXT CHECK(toggle_ac_overhead_pay_NewRequest IN ('On', 'Off')),  
    -- HR
    toggleHR TEXT CHECK(toggleHR IN ('On', 'Off')),  
    toggleADD TEXT CHECK(toggleADD IN ('On', 'Off')),  
    toggleAddCourse TEXT CHECK(toggleAddCourse IN ('On', 'Off')),  
    toggleEditCourse TEXT CHECK(toggleEditCourse IN ('On', 'Off')),  
    toggleDeleteCourse TEXT CHECK(toggleDeleteCourse IN ('On', 'Off')),
    toggleAddLeave TEXT CHECK(toggleAddLeave IN ('On', 'Off')),  
    toggleEditLeave TEXT CHECK(toggleEditLeave IN ('On', 'Off')),  
    toggleDeleteLeave TEXT CHECK(toggleDeleteLeave IN ('On', 'Off')),  
    toggleAddAsset TEXT CHECK(toggleAddAsset IN ('On', 'Off')),  
    toggleEditAsset TEXT CHECK(toggleEditAsset IN ('On', 'Off')),  
    toggleDeleteAsset TEXT CHECK(toggleDeleteAsset IN ('On', 'Off')),  
    toggleAddHoliday TEXT CHECK(toggleAddHoliday IN ('On', 'Off')),  
    toggleEditHoliday TEXT CHECK(toggleEditHoliday IN ('On', 'Off')),  
    toggleDeleteHoliday TEXT CHECK(toggleDeleteHoliday IN ('On', 'Off')),  
    toggleHRLeaves TEXT CHECK(toggleHRLeaves IN ('On', 'Off')),  
    toggleLeaveOverview TEXT CHECK(toggleLeaveOverview IN ('On', 'Off')),  
    togglePendingApprovals TEXT CHECK(togglePendingApprovals IN ('On', 'Off')),  
    toggleApproveRejectLeave TEXT CHECK(toggleApproveRejectLeave IN ('On', 'Off')),  
    toggleDeleteLeavePending TEXT CHECK(toggleDeleteLeavePending IN ('On', 'Off')),  
    toggleLeaveStats TEXT CHECK(toggleLeaveStats IN ('On', 'Off')),  
    toggleLeaveAllocation TEXT CHECK(toggleLeaveAllocation IN ('On', 'Off')),
    toggleAddLeaveAllocation TEXT CHECK(toggleAddLeaveAllocation IN ('On', 'Off')), 
    toggleEditLeaveAllocation TEXT CHECK(toggleEditLeaveAllocation IN ('On', 'Off')), 
    toggleDeleteLeaveAllocation TEXT CHECK(toggleDeleteLeaveAllocation IN ('On', 'Off')), 
    toggleHRProfile TEXT CHECK(toggleHRProfile IN ('On', 'Off')), 
    toggleUpdateBio TEXT CHECK(toggleUpdateBio IN ('On', 'Off')), 
    toggleUpdateCourse TEXT CHECK(toggleUpdateCourse IN ('On', 'Off')), 
    toggleUpdateAssets TEXT CHECK(toggleUpdateAssets IN ('On', 'Off')), 
    -- Enquiry
    toggleEnquiry TEXT CHECK(toggleEnquiry IN ('On', 'Off')), 
    toggleCreateEnquiry TEXT CHECK(toggleCreateEnquiry IN ('On', 'Off')), 
    toggleEditEnquiry TEXT CHECK(toggleEditEnquiry IN ('On', 'Off')), 
    toggleDeleteEnquiry TEXT CHECK(toggleDeleteEnquiry IN ('On', 'Off')), 
    -- Profile
    toggleProfile TEXT CHECK(toggleProfile IN ('On', 'Off')), 
    toggleAccountHub TEXT CHECK(toggleAccountHub IN ('On', 'Off')), 
    togglePersonalDetails TEXT CHECK(togglePersonalDetails IN ('On', 'Off')), 
    toggleprof_Leaves TEXT CHECK(toggleprof_Leaves IN ('On', 'Off')), 
    toggle_prof_Courses TEXT CHECK(toggle_prof_Courses IN ('On', 'Off')), 
    toggle_prof_Payslip TEXT CHECK(toggle_prof_Payslip IN ('On', 'Off')), 
    toggle_prof_Assets TEXT CHECK(toggle_prof_Assets IN ('On', 'Off')), 
    toggle_prof_TimeSheet TEXT CHECK(toggle_prof_TimeSheet IN ('On', 'Off')), 
    toggle_prof_Project TEXT CHECK(toggle_prof_Project IN ('On', 'Off')), 
    toggle_prof_Estimation TEXT CHECK(toggle_prof_Estimation IN ('On', 'Off')), 
    toggle_prof_Overhead TEXT CHECK(toggle_prof_Overhead IN ('On', 'Off')), 
    toggle_prof_Service TEXT CHECK(toggle_prof_Service IN ('On', 'Off')), 
    toggle_prof_Warranty TEXT CHECK(toggle_prof_Warranty IN ('On', 'Off')), 
    toggleProfPurchaseRequest TEXT CHECK(toggleProfPurchaseRequest IN ('On', 'Off')), 
    togglecreate_PR_All TEXT CHECK(togglecreate_PR_All IN ('On', 'Off')), 
    togglec_PR_all_create TEXT CHECK(togglec_PR_all_create IN ('On', 'Off')), 
    toggle_PR_all_view TEXT CHECK(toggle_PR_all_view IN ('On', 'Off')), 
    toggle_PR_all_approve TEXT CHECK(toggle_PR_all_approve IN ('On', 'Off')), 
    togglecreate_PR_Involved TEXT CHECK(togglecreate_PR_Involved IN ('On', 'Off')), 
    togglec_PR_Involved_create TEXT CHECK(togglec_PR_Involved_create IN ('On', 'Off')), 
    toggle_PR_Involved_view TEXT CHECK(toggle_PR_Involved_view IN ('On', 'Off')), 
    toggle_PR_Involved_approve TEXT CHECK(toggle_PR_Involved_approve IN ('On', 'Off')), 
    toggleProjectRequest TEXT CHECK(toggleProjectRequest IN ('On', 'Off')), 
    toggleprf_prj_NewRequest TEXT CHECK(toggleprf_prj_NewRequest IN ('On', 'Off')), 
    togglePendingRequest TEXT CHECK(togglePendingRequest IN ('On', 'Off')), 
    toggleRequestedList TEXT CHECK(toggleRequestedList IN ('On', 'Off')), 
    toggle_prof_approveprj TEXT CHECK(toggle_prof_approveprj IN ('On', 'Off')), 
    toggleProfPurchaseOrder TEXT CHECK(toggleProfPurchaseOrder IN ('On', 'Off')), 
    toggleProf_po_View_All TEXT CHECK(toggleProf_po_View_All IN ('On', 'Off')), 
    toggleProf_po_View_Involved TEXT CHECK(toggleProf_po_View_Involved IN ('On', 'Off')), 
    togglePaymentRequest TEXT CHECK(togglePaymentRequest IN ('On', 'Off')),
    toggleView_pro_Request_view_all TEXT CHECK(toggleView_pro_Request_view_all IN ('On', 'Off')),
    toggleView_pro_Request_view_involved TEXT CHECK(toggleView_pro_Request_view_involved IN ('On', 'Off')),
    toggleView_pro_Request_Create_all TEXT CHECK(toggleView_pro_Request_Create_all IN ('On', 'Off')),
    toggleView_pro_Request_Create_involved TEXT CHECK(toggleView_pro_Request_Create_involved IN ('On', 'Off')),
    toggle_prof_claims TEXT CHECK(toggle_prof_claims IN ('On', 'Off')),
    toggle_prof_view_involved_Claims TEXT CHECK(toggle_prof_view_involved_Claims IN ('On', 'Off')),
    toggle_prof_view_all_Claims TEXT CHECK(toggle_prof_view_all_Claims IN ('On', 'Off')),
    toggle_prof_view_create_Claims TEXT CHECK(toggle_prof_view_create_Claims IN ('On', 'Off')),
    toggleDeliveryOrders TEXT CHECK(toggleDeliveryOrders IN ('On', 'Off')),
    toggleViewallDO TEXT CHECK(toggleViewallDO IN ('On', 'Off')),
    toggleViewinvolvedDO TEXT CHECK(toggleViewinvolvedDO IN ('On', 'Off')),
    toggleprofSuppliers TEXT CHECK(toggleprofSuppliers IN ('On', 'Off')), 
    toggleprofEditpurSupplier TEXT CHECK(toggleprofEditpurSupplier IN ('On', 'Off')), 
    toggleprofDeletepurSupplier TEXT CHECK(toggleprofDeletepurSupplier IN ('On', 'Off')), 
    toggleprofAddpurSupplier TEXT CHECK(toggleprofAddpurSupplier IN ('On', 'Off')), 
    -- Projects
    toggleProjects TEXT CHECK(toggleProjects IN ('On', 'Off')), 
    toggleDashboard TEXT CHECK(toggleDashboard IN ('On', 'Off')), 
    toggleAllProjects TEXT CHECK(toggleAllProjects IN ('On', 'Off')), 
    toggleInvolvedProjects TEXT CHECK(toggleInvolvedProjects IN ('On', 'Off')), 
    toggleEditPM TEXT CHECK(toggleEditPM IN ('On', 'Off')), 
    toggleEditAllProjects TEXT CHECK(toggleEditAllProjects IN ('On', 'Off')), 
    toggleProjectStatus TEXT CHECK(toggleProjectStatus IN ('On', 'Off')), 
    toggleOnlyPMProjects TEXT CHECK(toggleOnlyPMProjects IN ('On', 'Off')), 
    toggleAllstatusProjects TEXT CHECK(toggleAllstatusProjects IN ('On', 'Off')), 
    toggleHoursEdit TEXT CHECK(toggleHoursEdit IN ('On', 'Off')), 
    toggleHoursView TEXT CHECK(toggleHoursView IN ('On', 'Off')), 
    toggleProjectDetails TEXT CHECK(toggleProjectDetails IN ('On', 'Off')), 
    toggleOverview TEXT CHECK(toggleOverview IN ('On', 'Off')), 
    toggleHrsView TEXT CHECK(toggleHrsView IN ('On', 'Off')), 
    toggleGeneratePR TEXT CHECK(toggleGeneratePR IN ('On', 'Off')), 
    togglePRJViewPR TEXT CHECK(togglePRJViewPR IN ('On', 'Off')), 
    toggleprjViewPO TEXT CHECK(toggleprjViewPO IN ('On', 'Off')), 
    toggleViewClaims TEXT CHECK(toggleViewClaims IN ('On', 'Off')), 
    togglePrjViewDO TEXT CHECK(togglePrjViewDO IN ('On', 'Off')), 
    toggleCreateDO TEXT CHECK(toggleCreateDO IN ('On', 'Off')), 
    togglePaymentRequests TEXT CHECK(togglePaymentRequests IN ('On', 'Off')), 
    toggleCreatePaymentRequest TEXT CHECK(toggleCreatePaymentRequest IN ('On', 'Off')), 
    -- Purchase
    togglePurchase TEXT CHECK(togglePurchase IN ('On', 'Off')), 
    togglePurchaseRequest TEXT CHECK(togglePurchaseRequest IN ('On', 'Off')), 
    toggleViewPRDetails TEXT CHECK(toggleViewPRDetails IN ('On', 'Off')), 
    toggleApproveAnyPR TEXT CHECK(toggleApproveAnyPR IN ('On', 'Off')), 
    toggleIssueAnyPO TEXT CHECK(toggleIssueAnyPO IN ('On', 'Off')), 
    toggleEditPR TEXT CHECK(toggleEditPR IN ('On', 'Off')), 
    toggleDeletePR TEXT CHECK(toggleDeletePR IN ('On', 'Off')), 
    togglePurchaseOrder TEXT CHECK(togglePurchaseOrder IN ('On', 'Off')), 
    toggleViewPODetails TEXT CHECK(toggleViewPODetails IN ('On', 'Off')), 
    toggleEditPO TEXT CHECK(toggleEditPO IN ('On', 'Off')), 
    togglePrintPO TEXT CHECK(togglePrintPO IN ('On', 'Off')), 
    toggleCreatePRAllProjects TEXT CHECK(toggleCreatePRAllProjects IN ('On', 'Off')), 
    toggleMaterialReceipt TEXT CHECK(toggleMaterialReceipt IN ('On', 'Off')), 
    toggleReceive TEXT CHECK(toggleReceive IN ('On', 'Off')), 
    toggleReceiptRecords TEXT CHECK(toggleReceiptRecords IN ('On', 'Off')), 
    togglePOUpdate TEXT CHECK(togglePOUpdate IN ('On', 'Off')), 
    togglepurSuppliers TEXT CHECK(togglepurSuppliers IN ('On', 'Off')), 
    toggleEditpurSupplier TEXT CHECK(toggleEditpurSupplier IN ('On', 'Off')), 
    toggleDeletepurSupplier TEXT CHECK(toggleDeletepurSupplier IN ('On', 'Off')), 
    toggleAddpurSupplier TEXT CHECK(toggleAddpurSupplier IN ('On', 'Off')), 
    -- Planner
    togglePlanner TEXT CHECK(togglePlanner IN ('On', 'Off')), 
    -- Resources
    toggleResources TEXT CHECK(toggleResources IN ('On', 'Off'))
);

INSERT INTO access_control (
    Employee_ID, 
    Accounts,
    toggleClient,
    toggleAddClient,
    toggleEditClient,
    toggleDeleteClient,
    toggleSuppliers,
    toggleAddSupplier,
    toggleEditSupplier,
    toggleDeleteSupplier,
    toggleExpenses,
    toggleInvoice,
    toggleNewInvoice,
    toggleEditInvoice,
    toggleDeleteInvoice,
    toggleViewInvoice,
    toggleOverHeadPayReq,
    toggle_ac_overhead_pay_NewRequest,
    toggleHR,
    toggleADD,
    toggleAddCourse,
    toggleEditCourse,
    toggleDeleteCourse,
    toggleAddLeave,
    toggleEditLeave,
    toggleDeleteLeave,
    toggleAddAsset,
    toggleEditAsset,
    toggleDeleteAsset,
    toggleAddHoliday,
    toggleEditHoliday,
    toggleDeleteHoliday,
    toggleHRLeaves,
    toggleLeaveOverview,
    togglePendingApprovals,
    toggleApproveRejectLeave,
    toggleDeleteLeavePending,
    toggleLeaveStats,
    toggleLeaveAllocation,
    toggleAddLeaveAllocation,
    toggleEditLeaveAllocation,
    toggleDeleteLeaveAllocation,
    toggleHRProfile,
    toggleUpdateBio,
    toggleUpdateCourse,
    toggleUpdateAssets,
    toggleEnquiry,
    toggleCreateEnquiry,
    toggleEditEnquiry,
    toggleDeleteEnquiry,
    toggleProfile,
    toggleAccountHub,
    togglePersonalDetails,
    toggleprof_Leaves,
    toggle_prof_Courses,
    toggle_prof_Payslip,
    toggle_prof_Assets,
    toggle_prof_TimeSheet,
    toggle_prof_Project,
    toggle_prof_Estimation,
    toggle_prof_Overhead,
    toggle_prof_Service,
    toggle_prof_Warranty,
    toggleProfPurchaseRequest,
    togglecreate_PR_All,
    togglec_PR_all_create,
    toggle_PR_all_view,
    toggle_PR_all_approve,
    togglecreate_PR_Involved,
    togglec_PR_Involved_create,
    toggle_PR_Involved_view,
    toggle_PR_Involved_approve,
    toggleProjectRequest,
    toggleprf_prj_NewRequest,
    togglePendingRequest,
    toggleRequestedList,
    toggle_prof_approveprj,
    toggleProfPurchaseOrder,
    toggleProf_po_View_All,
    toggleProf_po_View_Involved,
    togglePaymentRequest,
    toggleView_pro_Request_view_all,
    toggleView_pro_Request_view_involved,
    toggleView_pro_Request_Create_all,
    toggleView_pro_Request_Create_involved,
    toggle_prof_claims,
    toggle_prof_view_involved_Claims,
    toggle_prof_view_all_Claims,
    toggle_prof_view_create_Claims,
    toggleDeliveryOrders,
    toggleViewallDO,
    toggleViewinvolvedDO,
    toggleprofSuppliers,
    toggleprofEditpurSupplier,
    toggleprofDeletepurSupplier,
    toggleprofAddpurSupplier,
    toggleProjects,
    toggleDashboard,
    toggleAllProjects,
    toggleInvolvedProjects,
    toggleEditPM,
    toggleEditAllProjects,
    toggleProjectStatus,
    toggleAllstatusProjects,
    toggleOnlyPMProjects,
    toggleHoursEdit,
    toggleHoursView,
    toggleProjectDetails,
    toggleOverview,
    toggleHrsView,
    toggleGeneratePR,
    togglePRJViewPR,
    toggleprjViewPO,
    toggleViewClaims,
    togglePrjViewDO,
    toggleCreateDO,
    togglePaymentRequests,
    toggleCreatePaymentRequest,
    togglePurchase,
    togglePurchaseRequest,
    toggleViewPRDetails,
    toggleApproveAnyPR,
    toggleIssueAnyPO,
    toggleEditPR,
    toggleDeletePR,
    togglePurchaseOrder,
    toggleViewPODetails,
    toggleEditPO,
    togglePrintPO,
    toggleCreatePRAllProjects,
    toggleMaterialReceipt,
    toggleReceive,
    toggleReceiptRecords,
    togglePOUpdate,
    togglepurSuppliers,
    toggleEditpurSupplier,
    toggleDeletepurSupplier,
    toggleAddpurSupplier,
    togglePlanner,
    toggleResources)
VALUES ('balaji', 
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On',
    'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On', 'On' 
);

CREATE TABLE employee_details (
    id INTEGER PRIMARY KEY,
    Full_Employee_ID TEXT NOT NULL,
    display_Name TEXT NOT NULL,
    Designation TEXT,
    Expense_Code TEXT,
    Email_Id TEXT,
    Race TEXT,
    Sector TEXT,
    Date_Joined DATE,
    Date_Left DATE,
    Employee_Status TEXT,
    UserName_Portal TEXT,
    Password_Portal TEXT,
    Nationality TEXT,
    Pass_Type TEXT,
    NRIC TEXT,
    FIN TEXT,
    WP TEXT,
    Passport_No TEXT,
    Passport_Exp_Date TEXT,
    DOB DATE,
    Phone_No TEXT,
    Personal_Mail TEXT,
    Address TEXT,
    Emergency_Contact TEXT,
    Emergency_Contact_Address TEXT,
    Relation_to_Employee TEXT,
    Basic REAL,
    Employee_cpf REAL,
    Employer_cpf REAL,
    Allowance_Housing REAL,
    Allowance_Transport REAL,
    Allowance_Phone REAL,
    Allowance_Others REAL,
    Fund_CDAC REAL,
    Fund_ECF REAL,
    Fund_MBMF REAL,
    Fund_SINDA REAL,
    Deduction_Housing REAL,
    Deduction_Transport REAL,
    Deduction_Phone REAL,
    Deduction_Others REAL,
    Levy REAL,
    SDL REAL,
    Total REAL,
    Rate_hr REAL,
    Rate_day REAL,
    Annual_Leave INTEGER,
    Pass_Exp_Date DATE,
    Date_of_Application DATE,
    Emergency_Contact_No INT
);

CREATE TABLE attended_courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Employee_ID TEXT NOT NULL,
    Course_Name TEXT NOT NULL,
    Date_Attained DATE,
    Expiry_Date DATE,
    UNIQUE(Employee_ID, Course_Name) 
);

CREATE TABLE issued_assets (
    id INTEGER PRIMARY KEY,
    Employee_ID TEXT NOT NULL,
    Asset_Type TEXT NOT NULL,
    Date_Issued DATE,
    Model TEXT,
    Serial_Number TEXT,
    Date_Returned DATE,
    FOREIGN KEY(Employee_ID) REFERENCES employee_details(Employee_ID)
);

CREATE TABLE cost_center (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL,
    expenses_name TEXT,
    hourly_rate FLOAT
);

CREATE TABLE vehicle (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Vehicle_name TEXT NOT NULL,
    Vehicle_number TEXT
);

CREATE TABLE Accommodation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Building_Name TEXT NOT NULL,
    Address_Line1 TEXT,
    Address_Line2 TEXT,
    Address_Line3 TEXT,
    Contact TEXT
);

CREATE TABLE expenses_values (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    type_values TEXT
);


CREATE TABLE GST (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    GST INTEGER NOT NULL,
    Date DATE
);

CREATE TABLE courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Course_Name TEXT NOT NULL
);

CREATE TABLE assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Asset_Name TEXT NOT NULL,
    Model TEXT,
    S_N TEXT,
    status TEXT
);

CREATE TABLE industry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    industry TEXT
);

CREATE TABLE projects_request(
    id INTEGER PRIMARY KEY,
    client TEXT NOT NULL,
    project_name TEXT NOT NULL,
    start_time DATETIME NULL,
    end_time DATETIME, 
    pm_status BOOLEAN NOT NULL DEFAULT '0',
    pe_status BOOLEAN NOT NULL DEFAULT '0',
    status VARCHAR(50),
    po_number VARCHAR(255),
    po_value INT,
    pm TEXT,
    pe TEXT,
    delivery_address TEXT,
    delivery_address2 TEXT;
    delivery_address3 TEXT;
    billing_address TEXT,
    billing_address2 TEXT;
    billing_address3 TEXT;
    budget TEXT,
    type TEXT,
    project_members TEXT,
    approved_status TEXT,
    requested_by TEXT,
    requested_date DATE,
    approved_by TEXT,
    approved_date DATE,
    created_by TEXT,
    created_date DATE
);

CREATE TABLE request_pmtable (
    project_id INTEGER NOT NULL,
    username VARCHAR(50),
    department_code VARCHAR(10) NOT NULL,
    hours FLOAT NOT NULL,
    added_hours FLOAT,
    total FLOAT,
    PRIMARY KEY (project_id, department_code)
);

CREATE TABLE projects(
    id INTEGER PRIMARY KEY,
    client TEXT NOT NULL,
    project_name TEXT NOT NULL,
    start_time DATETIME NULL,
    end_time DATETIME, 
    pm_status BOOLEAN NOT NULL DEFAULT '0',
    pe_status BOOLEAN NOT NULL DEFAULT '0',
    status VARCHAR(50),
    po_number VARCHAR(255),
    po_value INT,
    pm TEXT,
    pe TEXT,
    delivery_address TEXT,
    delivery_address2 TEXT;
    delivery_address3 TEXT;
    billing_address TEXT,
    billing_address2 TEXT;
    billing_address3 TEXT;
    budget TEXT,
    type TEXT,
    project_members TEXT
);

CREATE TABLE employees (
    employee_id TEXT,
    project_id INTEGER,
    client TEXT,
    project_name TEXT NOT NULL,
    date DATE,
    hours_worked FLOAT,
    department_code INTEGER NOT NULL,
    pm_status BOOLEAN NOT NULL DEFAULT '0',
    FOREIGN KEY (employee_id) REFERENCES admin_user (username),
    FOREIGN KEY (department_code) REFERENCES departments (department_code),
    FOREIGN KEY (project_id) REFERENCES projects (id),
    FOREIGN KEY (project_name) REFERENCES projects (project_name),
    FOREIGN KEY (employee_id) REFERENCES users (id),
    FOREIGN KEY (client) REFERENCES projects (client)
);

CREATE TABLE workingHours (
    entryID INTEGER PRIMARY KEY AUTOINCREMENT,
    section_code INT,
    projectID INT,
    departmentID INT,
    employeeID text,
    workingDate DATE,
    hoursWorked DECIMAL(5, 2),
    project_name TEXT,
    client TEXT,
    formatted_date DATE,
    overtime_1_5 FLOAT,
    overtime_2_0 FLOAT,
    totalhours FLOAT,
    total_cost FLOAT,
    FOREIGN KEY (projectID) REFERENCES projects(id),
    FOREIGN KEY (departmentID) REFERENCES departments(department_code),
    FOREIGN KEY (employeeID) REFERENCES employees(employee_id)
);

CREATE TABLE pmtable (
    project_id INTEGER NOT NULL,
    username VARCHAR(50),
    department_code VARCHAR(10) NOT NULL,
    hours FLOAT NOT NULL,
    added_hours FLOAT,
    total FLOAT,
    PRIMARY KEY (project_id, department_code)
);

CREATE TABLE alloc_hrs_pmtable (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    username VARCHAR(50),
    department_code VARCHAR(10) NOT NULL,
    total FLOAT,
    date_added Date 
);

CREATE TABLE manual_entry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    username VARCHAR(50),
    department_code INT(10) NOT NULL,
    cost FLOAT NOT NULL,
    gst_value FLOAT,
    total FLOAT,
    cost_center_id TEXT,
    Exchange_rate FLOAT,
    Discount FLOAT
);

CREATE TABLE enquiries (
    EnquiryNumber INTEGER PRIMARY KEY AUTOINCREMENT,
    Industry TEXT,
    Client TEXT,
    Name TEXT,
    status CHAR,
    SiteOrEndUser TEXT,
    EnquiryReceived TEXT,
    SubmitBeforeDate TEXT,
    DateOfSubmission TEXT,
    RevisionNumber INTEGER,
    EstimateValue INTEGER,
    contact TEXT,
    Email TEXT,
    currency TEXT,
    PhoneNumber TEXT,
    assigned_to TEXT
);

ALTER TABLE enquiries ADD assigned_to TEXT;

CREATE TABLE leaves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employeeID VARCHAR(255),
    section_code INT,
    leave_type TEXT,
    leave_date DATE,
    leave_duration TEXT,
    department_code INT,
    status TEXT,
    approved_by TEXT,
    approved_date DATE,
    temp_id INT
);

CREATE TABLE leaves_approved (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employeeID VARCHAR(255),
    section_code INT,
    leave_type TEXT,
    start_date DATE,
    end_date DATE,
    number_of_days TEXT,
    department_code INT,
    status TEXT,
    approved_by TEXT,
    approved_date DATE
);

CREATE TABLE admin_leave_allocation(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    EmployeeID VARCHAR(255),
    Medical INT,
    Casual INT,
    Annual INT,
    Maternity INT,
    Paternity INT,
    Public INT,
    Unpaid INT,
    Year INT,
    Start_Date INT
);

CREATE TABLE public_holidays (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE,
    discription TEXT
);


CREATE TABLE claimed_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_by TEXT,
  date DATE,
  projectid INTEGER,
  project_name TEXT,
  Category TEXT,
  Category_code INTEGER,
  Sub_Category TEXT,
  Sub_Category_code INTEGER,
  vendor TEXT,
  itemname TEXT,
  Currency TEXT,
  comments TEXT,
  Rate REAL,
  invoice_number TEXT,
  amount REAL,
  gst_percent REAL,
  gst_value REAL,
  gst REAL,
  total REAL,
  claim_no TEXT,
  claim_type TEXT,
  attach_doc_name TEXT,
  supplier_name TEXT
);


CREATE TABLE claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_id TEXT,
  claim_by TEXT,
  claim_date DATE,
  approved_date DATE,
  approved_by DATE,
  last_update DATE,
  comments TEXT,
  status TEXT,
  Reference_Code TEXT,
  Edit_status TEXT,
  claim_Total REAL,
  claim_type TEXT,
  amount REAL,
  gst_value REAL,
  balance REAL
);


CREATE TABLE expences_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_by TEXT,
  date DATE,
  projectid INTEGER,
  project_name TEXT,
  Category TEXT,
  Category_code INTEGER,
  Sub_Category TEXT,
  Sub_Category_code INTEGER,
  Sub_Sub_Category TEXT,
  Sub_Sub_Category_code INTEGER,
  vendor TEXT,
  itemname TEXT,
  Currency TEXT,
  comments TEXT,
  Rate REAL,
  invoice_number TEXT,
  amount REAL,
  gst_percent REAL,
  gst_value REAL,
  Remarks TEXT,
  gst REAL,
  total REAL,
  additional_input TEXT,
  claim_no INTEGER
);

CREATE TABLE Expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_id TEXT,
  claim_by TEXT,
  claim_date DATE,
  approved_date DATE,
  approved_by DATE,
  last_update DATE,
  comments TEXT,
  status TEXT,
  Reference_Code TEXT,
  Edit_status TEXT,
  claim_Total REAL
);

CREATE TABLE employee_bills(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT,
    site TEXT,
    vendor TEXT,
    item_name TEXT,
    invoice_number TEXT,
    invoice_date DATE,
    purchase_type TEXT,
    amount REAL,
    bill_category TEXT,
    currentdate DATE,
    username TEXT,
    generate INTEGER DEFAULT 0, 
    FOREIGN KEY (username) REFERENCES users (name)
);

CREATE TABLE pr_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INT,
    pr_number TEXT,
    Part_No TEXT,
    item TEXT,
    quantity INT,
    uom TEXT,
    Unit_Price REAL,
    total TEXT,
    GST REAL,
    excepted_date DATE,
    status TEXT
);

CREATE TABLE created_pr (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    PR_no TEXT,
    project_id INTEGER,
    Supplier_Name TEXT,
    phone_number INTEGER,
    PR_Date DATE,
    created_by TEXT,
    Quote_Ref TEXT,
    Expenses INTEGER,
    Delivery TEXT,
    Address_Line1 TEXT,
    Address_Line2 TEXT,
    Payment_Terms TEXT,
    Currency TEXT,
    Exchange_rate FLOAT,
    status TEXT,
    total TEXT,
    Attn TEXT,
    Supplier_address1 TEXT, 
    Supplier_address2 TEXT,
    Supplier_address3 TEXT,
    Company_name TEXT,
    leat_time TEXT,
    comments TEXT,
    approved_by TEXT,
    filename text,
    original_creater TEXT,
    Discount FLOAT
);

CREATE TABLE po_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INT,
    PO_number TEXT,
    Part_No TEXT,
    item TEXT,
    quantity INT,
    uom TEXT,
    Unit_Price REAL,
    total TEXT,
    GST REAL,
    excepted_date DATE,
    status TEXT
);

CREATE TABLE created_po (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    PO_no TEXT,
    project_id INTEGER,
    Supplier_Name TEXT,
    phone_number INTEGER,
    PO_Date DATE,
    created_by TEXT,
    Quote_Ref TEXT,
    Expenses INTEGER,
    Delivery TEXT,
    Address_Line1 TEXT,
    Address_Line2 TEXT,
    Payment_Terms TEXT,
    Currency TEXT,
    status TEXT,
    total TEXT,
    Attn TEXT,
    Supplier_address1 TEXT, 
    Supplier_address2 TEXT,
    Supplier_address3 TEXT,
    Company_name TEXT,
    leat_time TEXT,
    comments TEXT,
    approved_by TEXT,
    PR_no_ref TEXT,
    PO_Issued_by TEXT,
    do_staus TEXT,
    payment_status TEXT,
    downpayment FLOAT,
    filename text,
    Exchange_rate FLOAT,
    Discount FLOAT
);

CREATE TABLE Delivery_Order (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  
    do_number TEXT NOT NULL,                 
    supplier_name TEXT NOT NULL,
    delivery_date DATE,
    status TEXT,
    po_number TEXT,
    filename text,
    comments TEXT
    UNIQUE (do_number, supplier_name)        
);

CREATE TABLE Material_Receipt (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    do_number TEXT NOT NULL,
    supplier_name TEXT NOT NULL,
    uom TEXT,
    po_number TEXT,
    item_name TEXT,
    part_number TEXT,
    received_date DATE,
    received_by TEXT,
    received_on_behalf_of TEXT,
    quantity INT,
    item_ref_code INT,
    filename TEXT,
    FOREIGN KEY (do_number, supplier_name) REFERENCES Delivery_Order(do_number, supplier_name) 
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE created_do (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    do_number TEXT,
    do_date DATE,
    proj_no INT,
    client text,
    client_add_l1 text,
    client_add_l2 text,
    client_add_l3 text,
    delivery text,
    delivery_add_l1 text,
    delivery_add_l2 text,
    delivery_add_l3 text,
    po_number TEXT,
    status TEXT,
    created_by TEXT,
    Project_Ref TEXT,
    Attn TEXT,
    Remarks text,
    Warranty text 
);

CREATE TABLE do_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    index_number TEXT,
    do_number TEXT,
    proj_no INT,
    status TEXT,
    item_name TEXT,
    qty FLOAT,
    Unit TEXT
);

CREATE TABLE client_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Client_code TEXT,
    reg_no TEXT,
    company_name TEXT,
    display_name TEXT,
    fax TEXT,
    office_no INT,
    website TEXT,
    billing_address1 TEXT,
    billing_address2 TEXT,
    billing_city TEXT,
    billing_postcode INT,
    billing_country TEXT,
    billing_state TEXT,
    delivery_address1 TEXT,
    delivery_address2 TEXT,
    delivery_city TEXT,
    delivery_postcode INT,
    delivery_country TEXT,
    delivery_state TEXT,
    contact1 TEXT,
    email1 TEXT,
    mobile1 INT,
    contact2 TEXT,
    email2 TEXT,
    mobile2 INT,
    contact3 TEXT,
    email3 TEXT,
    mobile3 INT,
    contact4 TEXT,
    email4 TEXT,
    mobile4 INT,
    industry_type TEXT
);

CREATE TABLE vendors_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_code TEXT,
    reg_no TEXT,
    company_name TEXT,
    display_name TEXT,
    office_no INT,
    website TEXT,
    billing_address1 TEXT,
    billing_address2 TEXT,
    city TEXT,
    postcode INT,
    country TEXT,
    state TEXT,
    contact1 TEXT,
    email1 TEXT,
    mobile1 INT,
    contact2 TEXT,
    email2 TEXT,
    mobile2 INT,
    contact3 TEXT,
    email3 TEXT,
    mobile3 INT,
    bank_name TEXT,
    tax_id INT,
    branch_details TEXT,
    currency TEXT,
    pay_terms TEXT,
    account_no INT,
    swift TEXT,
    ifsc TEXT,
    product_catgory TEXT,
    brand TEXT,
    Details TEXT
);

CREATE TABLE resource_type (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT NOT NULL UNIQUE, 
    EF TEXT CHECK (EF IN ('On', 'Off')),
    EL TEXT CHECK (EL IN ('On', 'Off')),
    MF TEXT CHECK (MF IN ('On', 'Off')),
    WE TEXT CHECK (WE IN ('On', 'Off')),
    GW TEXT CHECK (GW IN ('On', 'Off')),
    TE TEXT CHECK (TE IN ('On', 'Off')),
    SS TEXT CHECK (SS IN ('On', 'Off')),
    SE TEXT CHECK (SE IN ('On', 'Off'))
);

CREATE TABLE employee_trade_qualification (
    id INTEGER AUTOINCREMENT,
    employee TEXT NOT NULL,
    trade TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (employee, trade)
);

CREATE TABLE payment_request(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pay_number TEXT,
    invoice_no TEXT,
    pay_date DATE,
    proj_no INT,
    po_number TEXT,
    status TEXT,
    created_by TEXT,
    approved_by TEXT,
    paid_by TEXT,
    amount FLOAT,
    invoice_file_name TEXT,
    paid_date DATE,
    approved_date DATE,
    overall_total_amount FLOAT,
    Invoice_date DATE,
    gst_stat TEXT,
    gst_value FLOAT,
    supplier_name TEXT,
    project_name TEXT,
    Terms FLOAT,
    time_period TEXT,
    balence FLOAT,
    comments TEXT,
    downpayment FLOAT
    Currency TEXT,
    Exchange_rate FLOAT
);

CREATE TABLE payment_req_items(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INT,
    pay_number TEXT,
    invoice_no TEXT,
    pay_date DATE,
    proj_no INT,
    po_NO TEXT,
    status TEXT,
    req_by TEXT,
    Part_No TEXT,
    item TEXT,
    req_quantity REAL,
    Unit_Price REAL,
    req_total REAL,
    amount_reuest REAL
);

CREATE TABLE payment_request_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pay_number TEXT,
    pay_date DATE,
    po_number TEXT,
    paid_by TEXT,
    amount FLOAT
);

CREATE TABLE roles(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee TEXT,
    primary_role TEXT,
    sencondary_role TEXT,
    primary_role_code INTEGER,
    sencondary_role_code INTEGER
);

CREATE TABLE user_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE overhead_budget (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL,
    expenses_name TEXT,
    budget FLOAT,
    added FLOAT,
    total FLOAT
);

CREATE TABLE created_invoice (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_no TEXT,
    inv_date DATE,
    po_number TEXT,
    external_po TEXT,
    attn text,
    payment_terms text,
    bank_name text,
    bank_acc_no INT,
    created_by TEXT,
    created_date DATE,
    bill_to_line1 text,
    bill_to_line2 text,
    bill_to_line3 text,
    delivary_to_line1 text,
    delivary_to_line2 text,
    delivary_to_line3 text,
    status TEXT,
    amount FLOAT,
    gst_value FLOAT,
    total FLOAT,
    Currency TEXT,
    exchange_rate FLOAT,
    gst TEXT,
    swift TEXT,
    brnach INTEGER,
    Terms INTEGER,
    B_client TEXT, 
    D_client TEXT,
    balence FLOAT,
    Recent_rec_On DATE,
    gst_percent FLOAT,
    comments TEXT,
    project_id INT
);

CREATE TABLE invoice_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_no TEXT,
    po_number TEXT,
    prj_id INT,
    item TEXT,
    quantity FLOAT,
    Unit_Price FLOAT,
    total FLOAT
);

CREATE TABLE invoice_pay_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inv_no TEXT,
    pay_date DATE,
    paid_by TEXT,
    amount FLOAT
);

CREATE TABLE department_hrs_alloc(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code INT,
    role TEXT,
    budget_hrs FLOAT,
    available_hrs FLOAT,
    annual_hrs FLOAT,
    medical_hrs FLOAT
);

CREATE TABLE bank_details(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    Bank_Name TEXT,
    Account_Number TEXT,
    Branch TEXT,
    Swift TEXT,
    Pay_Now TEXT
);

CREATE TABLE user_tasks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name TEXT,
    assigend_to TEXT,
    bucket TEXT,
    progress TEXT,
    priority TEXT,
    start_date DATE,
    due_date DATE,
    label TEXT,
    notes TEXT,
    checklist TEXT,
    attachemnt_file TEXT,
    created_by TEXT,
    created_date DATE
);




