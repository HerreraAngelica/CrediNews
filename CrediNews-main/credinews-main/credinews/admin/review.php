<?php
require_once '../config.php';

// Check if user is logged in and has admin or reviewer role
if (!isLoggedIn()) {
    redirect('../login.php', 'Please login to access the dashboard', 'warning');
}

if (!isAdminOrReviewer()) {
    redirect('../index.php', 'You do not have permission to access this page', 'danger');
}

// Check if report ID is provided
if (!isset($_GET['id']) || empty($_GET['id'])) {
    redirect('reports.php', 'Invalid report ID', 'danger');
}

$reportId = (int)$_GET['id'];
$userId = $_SESSION['user_id'];
$errors = [];
$success = false;

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = isset($_POST['action']) ? $_POST['action'] : '';
    $comments = isset($_POST['comments']) ? trim($_POST['comments']) : '';
    
    if (empty($action) || !in_array($action, ['approve', 'reject'])) {
        $errors[] = "Invalid action";
    }
    
    if (empty($errors)) {
        $status = ($action === 'approve') ? 'approved' : 'rejected';
        $articleStatus = ($action === 'approve') ? 'verified' : 'fake';
        
        // Update report status
        $stmt = $conn->prepare("UPDATE reports SET review_status = ?, reviewer_id = ?, review_date = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->bind_param("sii", $status, $userId, $reportId);
        
        if ($stmt->execute()) {
            // Get article ID
            $stmt = $conn->prepare("SELECT article_id FROM reports WHERE id = ?");
            $stmt->bind_param("i", $reportId);
            $stmt->execute();
            $result = $stmt->get_result();
            $report = $result->fetch_assoc();
            $articleId = $report['article_id'];
            
            // Update article status
            $stmt = $conn->prepare("UPDATE articles SET status = ? WHERE id = ?");
            $stmt->bind_param("si", $articleStatus, $articleId);
            $stmt->execute();
            
            // Log the action
            logAction($userId, "Report $status", "report", $reportId);
            
            $success = true;
        } else {
            $errors[] = "Failed to update report status. Please try again.";
        }
    }
}

// Get report details
$stmt = $conn->prepare("SELECT r.*, a.title, a.content, a.source, a.submission_date, a.encrypted, u.username 
                      FROM reports r 
                      JOIN articles a ON r.article_id = a.id 
                      JOIN users u ON a.user_id = u.id 
                      WHERE r.id = ?");
$stmt->bind_param("i", $reportId);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    redirect('reports.php', 'Report not found', 'danger');
}

$report = $result->fetch_assoc();

// Decrypt content if encrypted
if ($report['encrypted']) {
    $report['content'] = decryptData($report['content']);
}

// Verify digital signature
$reportData = $report['article_id'] . $report['credibility_score'] . $report['analysis_text'];
$signatureValid = verifySignature($reportData, $report['digital_signature']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Review Report - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
    <div class="d-flex" id="wrapper">
        <!-- Sidebar -->
        <div class="bg-gradient-primary sidebar" id="sidebar-wrapper">
            <div class="sidebar-brand text-white">
                <div class="sidebar-brand-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <div class="sidebar-brand-text mx-3"><?php echo APP_NAME; ?> Admin</div>
            </div>
            
            <hr class="sidebar-divider my-0">
            
            <ul class="nav flex-column">
                <li class="nav-item">
                    <a class="nav-link" href="dashboard.php">
                        <i class="fas fa-fw fa-tachometer-alt"></i>
                        <span>Dashboard</span>
                    </a>
                </li>
                
                <li class="nav-item">
                    <a class="nav-link active" href="reports.php">
                        <i class="fas fa-fw fa-clipboard-check"></i>
                        <span>Review Reports</span>
                    </a>
                </li>
                
                <li class="nav-item">
                    <a class="nav-link" href="articles.php">
                        <i class="fas fa-fw fa-newspaper"></i>
                        <span>Manage Articles</span>
                    </a>
                </li>
                
                <?php if (hasRole('admin')): ?>
                <li class="nav-item">
                    <a class="nav-link" href="users.php">
                        <i class="fas fa-fw fa-users"></i>
                        <span>Manage Users</span>
                    </a>
                </li>
                
                <li class="nav-item">
                    <a class="nav-link" href="settings.php">
                        <i class="fas fa-fw fa-cog"></i>
                        <span>Settings</span>
                    </a>
                </li>
                <?php endif; ?>
                
                <hr class="sidebar-divider">
                
                <li class="nav-item">
                    <a class="nav-link" href="../index.php">
                        <i class="fas fa-fw fa-home"></i>
                        <span>Back to Site</span>
                    </a>
                </li>
                
                <li class="nav-item">
                    <a class="nav-link" href="../logout.php">
                        <i class="fas fa-fw fa-sign-out-alt"></i>
                        <span>Logout</span>
                    </a>
                </li>
            </ul>
        </div>
        
        <!-- Page Content -->
        <div id="page-content-wrapper" class="bg-light">
            <!-- Topbar -->
            <nav class="navbar navbar-expand navbar-light bg-white topbar mb-4 static-top shadow">
                <div class="container-fluid">
                    <button class="btn btn-link d-md-none rounded-circle me-3" id="sidebarToggle">
                        <i class="fa fa-bars"></i>
                    </button>
                    
                    <h1 class="h3 mb-0 text-gray-800">Review Report</h1>
                    
                    <ul class="navbar-nav ms-auto">
                        <li class="nav-item dropdown no-arrow">
                            <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown">
                                <span class="me-2 d-none d-lg-inline text-gray-600 small"><?php echo $_SESSION['username']; ?></span>
                                <i class="fas fa-user-circle fa-fw"></i>
                            </a>
                            <div class="dropdown-menu dropdown-menu-end shadow">
                                <a class="dropdown-item" href="../profile.php">
                                    <i class="fas fa-user fa-sm fa-fw me-2 text-gray-400"></i>
                                    Profile
                                </a>
                                <div class="dropdown-divider"></div>
                                <a class="dropdown-item" href="../logout.php">
                                    <i class="fas fa-sign-out-alt fa-sm fa-fw me-2 text-gray-400"></i>
                                    Logout
                                </a>
                            </div>
                        </li>
                    </ul>
                </div>
            </nav>
            
            <!-- Begin Page Content -->
            <div class="container-fluid">
                <!-- Page Heading -->
                <div class="d-sm-flex align-items-center justify-content-between mb-4">
                    <h1 class="h3 mb-0 text-gray-800">Review Report #<?php echo $reportId; ?></h1>
                    <a href="reports.php" class="d-none d-sm-inline-block btn btn-sm btn-secondary shadow-sm">
                        <i class="fas fa-arrow-left fa-sm text-white-50"></i> Back to Reports
                    </a>
                </div>
                
                <?php if (!empty($errors)): ?>
                    <div class="alert alert-danger">
                        <ul class="mb-0">
                            <?php foreach ($errors as $error): ?>
                                <li><?php echo $error; ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle me-2"></i>
                        Report has been successfully <?php echo $_POST['action'] === 'approve' ? 'approved' : 'rejected'; ?>.
                    </div>
                    <div class="text-center mb-4">
                        <a href="reports.php" class="btn btn-primary">Back to Reports</a>
                    </div>
                <?php else: ?>
                    <!-- Report Details -->
                    <div class="row">
                        <!-- Article Information -->
                        <div class="col-lg-6">
                            <div class="card shadow mb-4">
                                <div class="card-header py-3">
                                    <h6 class="m-0 font-weight-bold text-primary">Article Information</h6>
                                </div>
                                <div class="card-body">
                                    <h5 class="card-title"><?php echo htmlspecialchars($report['title']); ?></h5>
                                    <p class="card-text small text-muted">
                                        Submitted by <?php echo htmlspecialchars($report['username']); ?> on 
                                        <?php echo date('M d, Y', strtotime($report['submission_date'])); ?>
                                    </p>
                                    <p class="card-text small text-muted">
                                        Source: <?php echo htmlspecialchars($report['source']); ?>
                                    </p>
                                    
                                    <div class="mt-4">
                                        <h6>Article Content:</h6>
                                        <div class="p-3 bg-light rounded">
                                            <div style="max-height: 300px; overflow-y: auto;">
                                                <?php echo nl2br(htmlspecialchars($report['content'])); ?>
                                            </div>
                                        </div>
                                        <?php if ($report['encrypted']): ?>
                                            <div class="mt-2 small text-muted">
                                                <i class="fas fa-lock me-1"></i> This content was encrypted and has been decrypted for review.
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- AI Analysis -->
                        <div class="col-lg-6">
                            <div class="card shadow mb-4">
                                <div class="card-header py-3">
                                    <h6 class="m-0 font-weight-bold text-primary">AI Analysis</h6>
                                </div>
                                <div class="card-body">
                                    <div class="text-center mb-4">
                                        <?php 
                                        $score = $report['credibility_score'];
                                        $scoreClass = 'danger';
                                        $scoreIcon = 'exclamation-triangle';
                                        $scoreText = 'Low Credibility';
                                        
                                        if ($score >= 80) {
                                            $scoreClass = 'success';
                                            $scoreIcon = 'check-circle';
                                            $scoreText = 'High Credibility';
                                        } elseif ($score >= 60) {
                                            $scoreClass = 'primary';
                                            $scoreIcon = 'check-circle';
                                            $scoreText = 'Generally Credible';
                                        } elseif ($score >= 40) {
                                            $scoreClass = 'warning';
                                            $scoreIcon = 'exclamation-circle';
                                            $scoreText = 'Mixed Credibility';
                                        } elseif ($score >= 20) {
                                            $scoreClass = 'danger';
                                            $scoreIcon = 'exclamation-triangle';
                                            $scoreText = 'Questionable';
                                        }
                                        ?>
                                        
                                        <div class="mb-3">
                                            <i class="fas fa-<?php echo $scoreIcon; ?> fa-3x text-<?php echo $scoreClass; ?>"></i>
                                        </div>
                                        <h2 class="text-<?php echo $scoreClass; ?>"><?php echo $score; ?>/100</h2>
                                        <h5 class="mb-0"><?php echo $scoreText; ?></h5>
                                    </div>
                                    
                                    <div class="mt-4">
                                        <h6>Analysis:</h6>
                                        <div class="p-3 bg-light rounded">
                                            <pre class="mb-0" style="white-space: pre-wrap;"><?php echo htmlspecialchars($report['analysis_text']); ?></pre>
                                        </div>
                                    </div>
                                    
                                    <div class="mt-4">
                                        <h6>Digital Signature:</h6>
                                        <div class="p-3 bg-light rounded">
                                            <code class="small"><?php echo $report['digital_signature']; ?></code>
                                        </div>
                                        <div class="mt-2 small <?php echo $signatureValid ? 'text-success' : 'text-danger'; ?>">
                                            <i class="fas fa-<?php echo $signatureValid ? 'check-circle' : 'exclamation-circle'; ?> me-1"></i>
                                            Signature is <?php echo $signatureValid ? 'valid' : 'invalid'; ?>.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Review Form -->
                    <?php if ($report['review_status'] === 'pending'): ?>
                        <div class="card shadow mb-4">
                            <div class="card-header py-3">
                                <h6 class="m-0 font-weight-bold text-primary">Review Decision</h6>
                            </div>
                            <div class="card-body">
                                <form action="review.php?id=<?php echo $reportId; ?>" method="POST">
                                    <div class="mb-3">
                                        <label for="comments" class="form-label">Review Comments (Optional)</label>
                                        <textarea class="form-control" id="comments" name="comments" rows="3"></textarea>
                                    </div>
                                    
                                    <div class="d-flex justify-content-center gap-3">
                                        <button type="submit" name="action" value="approve" class="btn btn-success">
                                            <i class="fas fa-check me-1"></i> Approve as Verified
                                        </button>
                                        <button type="submit" name="action" value="reject" class="btn btn-danger">
                                            <i class="fas fa-times me-1"></i> Reject as Fake News
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    <?php else: ?>
                        <div class="card shadow mb-4">
                            <div class="card-header py-3">
                                <h6 class="m-0 font-weight-bold text-primary">Review Status</h6>
                            </div>
                            <div class="card-body text-center">
                                <?php 
                                $reviewStatusClass = 'secondary';
                                $reviewStatusIcon = 'info-circle';
                                $reviewStatusText = 'Unknown';
                                
                                switch ($report['review_status']) {
                                    case 'approved':
                                        $reviewStatusClass = 'success';
                                        $reviewStatusIcon = 'check-circle';
                                        $reviewStatusText = 'Approved as Verified';
                                        break;
                                    case 'rejected':
                                        $reviewStatusClass = 'danger';
                                        $reviewStatusIcon = 'times-circle';
                                        $reviewStatusText = 'Rejected as Fake News';
                                        break;
                                }
                                ?>
                                
                                <div class="mb-3">
                                    <i class="fas fa-<?php echo $reviewStatusIcon; ?> fa-3x text-<?php echo $reviewStatusClass; ?>"></i>
                                </div>
                                <h4 class="text-<?php echo $reviewStatusClass; ?>"><?php echo $reviewStatusText; ?></h4>
                                
                                <?php if ($report['reviewer_id']): ?>
                                    <?php 
                                    // Get reviewer name
                                    $stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
                                    $stmt->bind_param("i", $report['reviewer_id']);
                                    $stmt->execute();
                                    $reviewerResult = $stmt->get_result();
                                    $reviewer = $reviewerResult->fetch_assoc();
                                    ?>
                                    <p class="mt-2 mb-0">
                                        Reviewed by <?php echo htmlspecialchars($reviewer['username']); ?> on 
                                        <?php echo date('M d, Y H:i', strtotime($report['review_date'])); ?>
                                    </p>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <!-- /.container-fluid -->
            
            <!-- Footer -->
            <footer class="sticky-footer bg-white">
                <div class="container my-auto">
                    <div class="copyright text-center my-auto">
                        <span>Copyright &copy; <?php echo APP_NAME . ' ' . date('Y'); ?></span>
                    </div>
                </div>
            </footer>
            <!-- End of Footer -->
        </div>
        <!-- End of Content Wrapper -->
    </div>
    <!-- End of Page Wrapper -->

    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="../assets/js/main.js"></script>
    <script>
        // Toggle the side navigation
        document.getElementById('sidebarToggle').addEventListener('click', function(e) {
            document.body.classList.toggle('sb-sidenav-toggled');
        });
    </script>
</body>
</html>