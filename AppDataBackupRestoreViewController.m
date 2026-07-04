#import "AppDataBackupRestoreViewController.h"
#import "common/UIButton+SafeConfiguration.h"
#import "AppDataBackupManager.h"
#import "BackupKeychainGroupsViewController.h"
#ifdef PROJECTX_TROLLSTORE
#import "PXDiagnostics.h"
#endif
#import <objc/message.h>

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (BOOL)openApplicationWithBundleID:(NSString *)bundleID;
@end

static NSString *PXBackupKeychainGroupsKey(NSString *bundleID) {
    return [NSString stringWithFormat:@"dataBackupKeychainGroups_%@", bundleID ?: @""];
}

static NSString * const PXBackupKeychainGroupsSavedNotification = @"com.hydra.projectx.backupKeychainGroupsSaved";

@interface AppDataBackupRestoreViewController ()
@property (nonatomic, strong) UILabel *appLabel;
@property (nonatomic, strong) UISwitch *includeGroupsSwitch;
@property (nonatomic, strong) UISwitch *includePrefsSwitch;
@property (nonatomic, strong) UISwitch *includeKeychainSwitch;
@property (nonatomic, strong) UIButton *keychainGroupsButton;

@property (nonatomic, copy) NSString *pendingAlertTitle;
@property (nonatomic, copy) NSString *pendingAlertMessage;
@property (nonatomic, copy) NSString *pendingCopyPath;
@end

@implementation AppDataBackupRestoreViewController

static void PXAttemptBringProjectXToFront(void) {
    NSString *selfBundle = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    if (!selfBundle.length) return;
    Class wsCls = NSClassFromString(@"LSApplicationWorkspace");
    if (!wsCls) return;
    id ws = [wsCls performSelector:@selector(defaultWorkspace)];
    if (!ws) return;
    if ([ws respondsToSelector:@selector(openApplicationWithBundleID:)]) {
        BOOL (*msgSend)(id, SEL, id) = (BOOL (*)(id, SEL, id))objc_msgSend;
        msgSend(ws, @selector(openApplicationWithBundleID:), selfBundle);
    }
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(_deliverPendingAlertIfPossible)
                                                 name:UIApplicationDidBecomeActiveNotification
                                               object:nil];
    
    // Set title based on whether we have a specific app
    if (self.appName) {
        self.title = [NSString stringWithFormat:@"%@ Backup & Restore", self.appName];
    } else {
        self.title = @"App Data Backup & Restore";
    }
    
    // Add Done button for the navigation bar
    UIBarButtonItem *doneButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                                               target:self
                                                                               action:@selector(dismissVC)];
    self.navigationItem.rightBarButtonItem = doneButton;
    
    // Create an app name/ID label to make it clear which app we're working with
    self.appLabel = [[UILabel alloc] init];
    if (self.bundleID) {
        NSString *displayText = self.appName ? 
            [NSString stringWithFormat:@"App: %@\nBundle ID: %@", self.appName, self.bundleID] : 
            [NSString stringWithFormat:@"Bundle ID: %@", self.bundleID];
        
        NSMutableAttributedString *attributedText = [[NSMutableAttributedString alloc] initWithString:displayText];
        
        // Add styling - make app name bold if we have it
        if (self.appName) {
            NSRange appNameRange = [displayText rangeOfString:self.appName];
            [attributedText addAttribute:NSFontAttributeName 
                                   value:[UIFont boldSystemFontOfSize:17] 
                                   range:appNameRange];
        }
        
        self.appLabel.attributedText = attributedText;
    } else {
        self.appLabel.text = @"No app selected";
    }
    
    self.appLabel.textAlignment = NSTextAlignmentCenter;
    self.appLabel.numberOfLines = 0;
    self.appLabel.font = [UIFont systemFontOfSize:16];
    self.appLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.appLabel];
    
    UILabel *descLabel = [[UILabel alloc] init];
    descLabel.text = @"Backup and Restore your app data easily.\n\nSelect an option below:";
    descLabel.textAlignment = NSTextAlignmentCenter;
    descLabel.numberOfLines = 0;
    descLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightRegular];
    descLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:descLabel];

    // Options
    UIStackView *optionsStack = [[UIStackView alloc] init];
    optionsStack.axis = UILayoutConstraintAxisVertical;
    optionsStack.spacing = 12;
    optionsStack.alignment = UIStackViewAlignmentFill;
    optionsStack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:optionsStack];

    UIView *(^makeOptionRow)(NSString *, UISwitch * __strong *) = ^UIView *(NSString *title, UISwitch * __strong *outSwitch) {
        UIView *row = [[UIView alloc] init];
        row.translatesAutoresizingMaskIntoConstraints = NO;

        UILabel *label = [[UILabel alloc] init];
        label.text = title;
        label.font = [UIFont systemFontOfSize:15 weight:UIFontWeightRegular];
        label.translatesAutoresizingMaskIntoConstraints = NO;

        UISwitch *sw = [[UISwitch alloc] init];
        sw.translatesAutoresizingMaskIntoConstraints = NO;

        [row addSubview:label];
        [row addSubview:sw];

        [NSLayoutConstraint activateConstraints:@[
            [label.leadingAnchor constraintEqualToAnchor:row.leadingAnchor],
            [label.centerYAnchor constraintEqualToAnchor:sw.centerYAnchor],
            [sw.trailingAnchor constraintEqualToAnchor:row.trailingAnchor],
            [sw.topAnchor constraintEqualToAnchor:row.topAnchor],
            [sw.bottomAnchor constraintEqualToAnchor:row.bottomAnchor]
        ]];

        if (outSwitch) {
            *outSwitch = sw;
        }

        return row;
    };

    UIView *groupsRow = makeOptionRow(@"Include App Groups (via entitlements)", &_includeGroupsSwitch);
    self.includeGroupsSwitch.on = YES;
    [optionsStack addArrangedSubview:groupsRow];

    UIView *prefsRow = makeOptionRow(@"Include Global Preferences (rare)", &_includePrefsSwitch);
    self.includePrefsSwitch.on = YES;
    [optionsStack addArrangedSubview:prefsRow];
    
    UIView *keychainRow = makeOptionRow(@"Include Keychain Items", &_includeKeychainSwitch);
    self.includeKeychainSwitch.on = NO; // Off by default - keychain backup is sensitive
    [optionsStack addArrangedSubview:keychainRow];

    // Keychain groups selector (enabled only when keychain toggle is on)
    self.keychainGroupsButton = [UIButton buttonWithType:UIButtonTypeSystem];
    if (@available(iOS 15.0, *)) {
    if ([UIButton buttonConfigurationClassExists]) {
        UIButtonConfiguration *cfg = [UIButtonConfiguration plainButtonConfiguration];
        cfg.title = @"Keychain Groups";
        cfg.image = [UIImage systemImageNamed:@"key.fill"]; 
        cfg.imagePlacement = NSDirectionalRectEdgeLeading;
        cfg.imagePadding = 6;
        cfg.baseForegroundColor = [UIColor systemBlueColor];
        [self.keychainGroupsButton safeSetConfiguration:cfg];
    } else {
        [self.keychainGroupsButton setTitle:@"Keychain Groups" forState:UIControlStateNormal];
    }
    } else {
        [self.keychainGroupsButton setTitle:@"Keychain Groups" forState:UIControlStateNormal];
    }
    self.keychainGroupsButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.keychainGroupsButton addTarget:self action:@selector(keychainGroupsTapped) forControlEvents:UIControlEventTouchUpInside];
    [optionsStack addArrangedSubview:self.keychainGroupsButton];

    [self.includeKeychainSwitch addTarget:self action:@selector(includeKeychainChanged:) forControlEvents:UIControlEventValueChanged];
    [self refreshKeychainGroupsButton];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(keychainGroupsSaved:)
                                                 name:PXBackupKeychainGroupsSavedNotification
                                               object:nil];
    
    UIStackView *buttonStack = [[UIStackView alloc] init];
    buttonStack.axis = UILayoutConstraintAxisVertical;
    buttonStack.spacing = 24;
    buttonStack.alignment = UIStackViewAlignmentCenter;
    buttonStack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:buttonStack];
    
    // Create stylish buttons with icons using UIButtonConfiguration (iOS 15+)
    UIButton *backupButton = [UIButton buttonWithType:UIButtonTypeSystem];
    if (@available(iOS 15.0, *)) {
    if ([UIButton buttonConfigurationClassExists]) {
        UIButtonConfiguration *backupConfig = [UIButtonConfiguration filledButtonConfiguration];
        backupConfig.title = @"Backup App Data";
        backupConfig.image = [UIImage systemImageNamed:@"arrow.down.doc.fill"];
        backupConfig.imagePlacement = NSDirectionalRectEdgeLeading;
        backupConfig.imagePadding = 8;
        backupConfig.contentInsets = NSDirectionalEdgeInsetsMake(12, 20, 12, 20);
        backupConfig.cornerStyle = UIButtonConfigurationCornerStyleMedium;
        backupConfig.baseBackgroundColor = [UIColor clearColor];
        backupConfig.baseForegroundColor = [UIColor systemBlueColor];
        [backupButton safeSetConfiguration:backupConfig];
    } else {
        [backupButton setTitle:@"Backup App Data" forState:UIControlStateNormal];
        [backupButton setImage:[UIImage systemImageNamed:@"arrow.down.doc.fill"] forState:UIControlStateNormal];
        backupButton.tintColor = [UIColor systemBlueColor];
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wdeprecated-declarations"
        backupButton.contentEdgeInsets = UIEdgeInsetsMake(12, 20, 12, 20);
        #pragma clang diagnostic pop
    }
    } else {
        [backupButton setTitle:@"Backup App Data" forState:UIControlStateNormal];
        [backupButton setImage:[UIImage systemImageNamed:@"arrow.down.doc.fill"] forState:UIControlStateNormal];
        backupButton.tintColor = [UIColor systemBlueColor];
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wdeprecated-declarations"
        backupButton.contentEdgeInsets = UIEdgeInsetsMake(12, 20, 12, 20);
        #pragma clang diagnostic pop
    }
    
    // Add rounded corners and border
    backupButton.layer.cornerRadius = 10;
    backupButton.layer.borderWidth = 1;
    backupButton.layer.borderColor = [UIColor systemBlueColor].CGColor;
    
    [backupButton addTarget:self action:@selector(backupButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [buttonStack addArrangedSubview:backupButton];
    
    // Create restore button with UIButtonConfiguration (iOS 15+)
    UIButton *restoreButton = [UIButton buttonWithType:UIButtonTypeSystem];
    if (@available(iOS 15.0, *)) {
    if ([UIButton buttonConfigurationClassExists]) {
        UIButtonConfiguration *restoreConfig = [UIButtonConfiguration filledButtonConfiguration];
        restoreConfig.title = @"Restore App Data";
        restoreConfig.image = [UIImage systemImageNamed:@"arrow.up.doc.fill"];
        restoreConfig.imagePlacement = NSDirectionalRectEdgeLeading;
        restoreConfig.imagePadding = 8;
        restoreConfig.contentInsets = NSDirectionalEdgeInsetsMake(12, 20, 12, 20);
        restoreConfig.cornerStyle = UIButtonConfigurationCornerStyleMedium;
        restoreConfig.baseBackgroundColor = [UIColor clearColor];
        restoreConfig.baseForegroundColor = [UIColor systemGreenColor];
        [restoreButton safeSetConfiguration:restoreConfig];
    } else {
        [restoreButton setTitle:@"Restore App Data" forState:UIControlStateNormal];
        [restoreButton setImage:[UIImage systemImageNamed:@"arrow.up.doc.fill"] forState:UIControlStateNormal];
        restoreButton.tintColor = [UIColor systemGreenColor];
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wdeprecated-declarations"
        restoreButton.contentEdgeInsets = UIEdgeInsetsMake(12, 20, 12, 20);
        #pragma clang diagnostic pop
    }
    } else {
        [restoreButton setTitle:@"Restore App Data" forState:UIControlStateNormal];
        [restoreButton setImage:[UIImage systemImageNamed:@"arrow.up.doc.fill"] forState:UIControlStateNormal];
        restoreButton.tintColor = [UIColor systemGreenColor];
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wdeprecated-declarations"
        restoreButton.contentEdgeInsets = UIEdgeInsetsMake(12, 20, 12, 20);
        #pragma clang diagnostic pop
    }
    
    // Add rounded corners and border
    restoreButton.layer.cornerRadius = 10;
    restoreButton.layer.borderWidth = 1;
    restoreButton.layer.borderColor = [UIColor systemGreenColor].CGColor;
    
    [restoreButton addTarget:self action:@selector(restoreButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    [buttonStack addArrangedSubview:restoreButton];
    
    [NSLayoutConstraint activateConstraints:@[
        // App label constraints
        [self.appLabel.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:20],
        [self.appLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:30],
        [self.appLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-30],
        
        // Description label constraints
        [descLabel.topAnchor constraintEqualToAnchor:self.appLabel.bottomAnchor constant:20],
        [descLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:30],
        [descLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-30],

        // Options stack constraints
        [optionsStack.topAnchor constraintEqualToAnchor:descLabel.bottomAnchor constant:20],
        [optionsStack.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:30],
        [optionsStack.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-30],
         
        // Button stack constraints
        [buttonStack.topAnchor constraintEqualToAnchor:optionsStack.bottomAnchor constant:30],
        [buttonStack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor]
    ]];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self _deliverPendingAlertIfPossible];
}

- (void)_deliverPendingAlertIfPossible {
    if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) {
        return;
    }
    if (!self.pendingAlertTitle.length || !self.pendingAlertMessage.length) {
        return;
    }
    if (self.presentedViewController) {
        return;
    }
    NSString *t = self.pendingAlertTitle;
    NSString *m = self.pendingAlertMessage;
    NSString *p = self.pendingCopyPath;
    self.pendingAlertTitle = nil;
    self.pendingAlertMessage = nil;
    self.pendingCopyPath = nil;

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:t
                                                                   message:m
                                                            preferredStyle:UIAlertControllerStyleAlert];
    if (p.length) {
        [alert addAction:[UIAlertAction actionWithTitle:@"Copy Path"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(__unused UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = p;
        }]];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)_presentResultAlertBestEffortWithTitle:(NSString *)title message:(NSString *)message copyPath:(NSString *)copyPath {
    if (!title.length || !message.length) return;
    if ([UIApplication sharedApplication].applicationState == UIApplicationStateActive && !self.presentedViewController) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        if (copyPath.length) {
            [alert addAction:[UIAlertAction actionWithTitle:@"Copy Path"
                                                      style:UIAlertActionStyleDefault
                                                    handler:^(__unused UIAlertAction * _Nonnull action) {
                [UIPasteboard generalPasteboard].string = copyPath;
            }]];
        }
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }

    // Queue and try to bring ProjectX back.
    self.pendingAlertTitle = title;
    self.pendingAlertMessage = message;
    self.pendingCopyPath = copyPath;
    PXAttemptBringProjectXToFront();
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)includeKeychainChanged:(UISwitch *)sender {
    if (sender.isOn && self.bundleID.length) {
        // Default selection: ALL groups (resolved lazily by picker on first open)
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        if (![defaults objectForKey:PXBackupKeychainGroupsKey(self.bundleID)]) {
            // Leave empty until picker resolves; still show button enabled.
        }
    }
    [self refreshKeychainGroupsButton];
}

- (void)keychainGroupsSaved:(NSNotification *)note {
    [self refreshKeychainGroupsButton];
}

- (void)refreshKeychainGroupsButton {
    BOOL enabled = self.includeKeychainSwitch.isOn;
    self.keychainGroupsButton.enabled = enabled;
    self.keychainGroupsButton.alpha = enabled ? 1.0 : 0.5;

    NSUInteger count = 0;
    if (self.bundleID.length) {
        id v = [[NSUserDefaults standardUserDefaults] objectForKey:PXBackupKeychainGroupsKey(self.bundleID)];
        if ([v isKindOfClass:[NSArray class]]) {
            count = [(NSArray *)v count];
        }
    }

    NSString *title = (count > 0) ? [NSString stringWithFormat:@"Keychain Groups (%lu)", (unsigned long)count] : @"Keychain Groups";
    if (@available(iOS 15.0, *)) {
    if ([UIButton buttonConfigurationClassExists]) {
        if (self.keychainGroupsButton.configuration) {
            UIButtonConfiguration *cfg = [self.keychainGroupsButton.configuration copy];
            cfg.title = title;
            [self.keychainGroupsButton setConfiguration:cfg];
            return;
        }
    }
    }
    [self.keychainGroupsButton setTitle:title forState:UIControlStateNormal];
}

- (void)keychainGroupsTapped {
    if (!self.includeKeychainSwitch.isOn) {
        return;
    }
    if (!self.bundleID.length) {
        return;
    }
    BackupKeychainGroupsViewController *vc = [[BackupKeychainGroupsViewController alloc] initWithBundleID:self.bundleID];
    [self.navigationController pushViewController:vc animated:YES];
}

- (void)dismissVC {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)backupButtonTapped {
    NSString *appIdentifier = self.appName ?: self.bundleID ?: @"this app";
#ifdef PROJECTX_TROLLSTORE
    [PXDiagnostics log:@"[backup-ui] backup tapped bundleID=%@ appName=%@", self.bundleID ?: @"", self.appName ?: @""];
#endif
    
    // Show a confirmation alert first
    UIAlertController *confirmAlert = [UIAlertController alertControllerWithTitle:@"Confirm Backup"
                                                                      message:[NSString stringWithFormat:@"Are you sure you want to backup data for %@?", appIdentifier]
                                                               preferredStyle:UIAlertControllerStyleAlert];
    
    [confirmAlert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
     [confirmAlert addAction:[UIAlertAction actionWithTitle:@"Backup" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        // Show processing alert
        UIAlertController *processingAlert = [UIAlertController alertControllerWithTitle:@"Backing Up"
                                                                          message:@"Please wait while we backup your app data..."
                                                                   preferredStyle:UIAlertControllerStyleAlert];
        [self presentViewController:processingAlert animated:YES completion:nil];
        
        PXBackupOptions options = 0;
        if (self.includeGroupsSwitch.on) {
            options |= PXBackupOptionIncludeAppGroups;
        }
        if (self.includePrefsSwitch.on) {
            options |= PXBackupOptionIncludePreferences;
        }
        if (self.includeKeychainSwitch.on) {
            options |= PXBackupOptionIncludeKeychain;
        }

         [[AppDataBackupManager shared] createBackupForBundleID:self.bundleID
                                                       appName:self.appName
                                                       options:options
                                                    completion:^(PXBackupResult *result, NSError *error) {
             [processingAlert dismissViewControllerAnimated:YES completion:^{
                  if (error) {
#ifdef PROJECTX_TROLLSTORE
                     [PXDiagnostics log:@"[backup-ui] backup failed error=%@", error.localizedDescription ?: @""];
#endif
                      UIAlertController *errAlert = [UIAlertController alertControllerWithTitle:@"Backup Failed"
                                                                                      message:error.localizedDescription ?: @"Unknown error"
                                                                               preferredStyle:UIAlertControllerStyleAlert];
                     [errAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                     [self _presentResultAlertBestEffortWithTitle:@"Backup Failed"
                                                         message:error.localizedDescription ?: @"Unknown error"
                                                        copyPath:nil];
                     return;
                 }

                NSMutableString *msg = [NSMutableString stringWithFormat:@"Backup created for %@.\n\nPath:\n%@", appIdentifier, result.backupDirectory ?: @"(unknown)"];
#ifdef PROJECTX_TROLLSTORE
                [PXDiagnostics log:@"[backup-ui] backup complete dir=%@ warnings=%@", result.backupDirectory ?: @"", result.warnings ?: @[]];
#endif
                if (result.warnings.count) {
                    [msg appendString:@"\n\nWarnings:\n"]; 
                    for (NSString *w in result.warnings) {
                        [msg appendFormat:@"- %@\n", w];
                    }
                }

                 [self _presentResultAlertBestEffortWithTitle:@"Backup Complete" message:msg copyPath:result.backupDirectory];
             }];
         }];
      }]];
    
    [self presentViewController:confirmAlert animated:YES completion:nil];
}

- (void)restoreButtonTapped {
    NSString *appIdentifier = self.appName ?: self.bundleID ?: @"this app";
#ifdef PROJECTX_TROLLSTORE
    [PXDiagnostics log:@"[restore-ui] restore tapped bundleID=%@ appName=%@", self.bundleID ?: @"", self.appName ?: @""];
#endif
    
    // Show a confirmation alert first with warning
    UIAlertController *confirmAlert = [UIAlertController alertControllerWithTitle:@"Confirm Restore"
                                                                      message:[NSString stringWithFormat:@"⚠️ Warning: This will replace the current data for %@ with backup data. This operation cannot be undone.\n\nAre you sure you want to continue?", appIdentifier]
                                                               preferredStyle:UIAlertControllerStyleAlert];
    
    [confirmAlert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [confirmAlert addAction:[UIAlertAction actionWithTitle:@"Restore" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        NSArray<NSString *> *backups = [[AppDataBackupManager shared] listBackupDirectoriesForBundleID:self.bundleID];
        if (!backups.count) {
            UIAlertController *noAlert = [UIAlertController alertControllerWithTitle:@"No Backups Found"
                                                                            message:@"No backups were found for this bundle ID. Create a backup first."
                                                                     preferredStyle:UIAlertControllerStyleAlert];
            [noAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:noAlert animated:YES completion:nil];
            return;
        }

        UIAlertController *picker = [UIAlertController alertControllerWithTitle:@"Select Backup"
                                                                        message:nil
                                                                 preferredStyle:UIAlertControllerStyleActionSheet];

        NSUInteger limit = MIN((NSUInteger)10, backups.count);
        for (NSUInteger i = 0; i < limit; i++) {
            NSString *dir = backups[i];
            NSString *title = dir.lastPathComponent;
            NSError *mErr = nil;
            NSDictionary *manifest = [[AppDataBackupManager shared] readManifestAtBackupDirectory:dir error:&mErr];
            if ([manifest isKindOfClass:[NSDictionary class]]) {
                NSString *ts = manifest[@"timestamp"]; 
                if ([ts isKindOfClass:[NSString class]] && ts.length) {
                    title = ts;
                }
            }

            [picker addAction:[UIAlertAction actionWithTitle:title
                                                      style:UIAlertActionStyleDefault
                                                    handler:^(UIAlertAction * _Nonnull action) {
                UIAlertController *processingAlert = [UIAlertController alertControllerWithTitle:@"Restoring"
                                                                                         message:@"Please wait while we restore your app data..."
                                                                                  preferredStyle:UIAlertControllerStyleAlert];
                [self presentViewController:processingAlert animated:YES completion:nil];

                 [[AppDataBackupManager shared] restoreBackupAtDirectory:dir
                                                                bundleID:self.bundleID
                                                                 appName:self.appName
                                                              completion:^(PXRestoreResult *result, NSError *error) {
                     [processingAlert dismissViewControllerAnimated:YES completion:^{
                         if (error) {
                             UIAlertController *errAlert = [UIAlertController alertControllerWithTitle:@"Restore Failed"
                                                                                              message:error.localizedDescription ?: @"Unknown error"
                                                                                       preferredStyle:UIAlertControllerStyleAlert];
                             [errAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                             [self _presentResultAlertBestEffortWithTitle:@"Restore Failed"
                                                                 message:error.localizedDescription ?: @"Unknown error"
                                                                copyPath:nil];
                             return;
                         }

                        NSMutableString *msg = [NSMutableString stringWithFormat:@"Data for %@ has been restored.", appIdentifier];
                        if (result.warnings.count) {
                            [msg appendString:@"\n\nWarnings:\n"]; 
                            for (NSString *w in result.warnings) {
                                [msg appendFormat:@"- %@\n", w];
                            }
                        }

                         [self _presentResultAlertBestEffortWithTitle:@"Restore Complete" message:msg copyPath:nil];
                     }];
                 }];
             }]];
        }

        [picker addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        if (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) {
            picker.popoverPresentationController.sourceView = self.view;
            picker.popoverPresentationController.sourceRect = CGRectMake(self.view.bounds.size.width/2.0, self.view.bounds.size.height, 1, 1);
        }
        [self presentViewController:picker animated:YES completion:nil];
    }]];
    
    [self presentViewController:confirmAlert animated:YES completion:nil];
}

@end
