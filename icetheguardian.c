/*
 *  _____ _____ _____                                           
 * |     |     |   __|                                          
 * |-   -|   --|   __|                                          
 * |_____|_____|_____|                                          
 *  _____ _          _____               _ _                ___ 
 * |_   _| |_ ___   |   __|_ _ ___ ___ _| |_|___ ___    _ _|_  |
 *   | | |   | -_|  |  |  | | | .'|  _| . | | .'|   |  | | |  _|
 *   |_| |_|_|___|  |_____|___|__,|_| |___|_|__,|_|_|   \_/|___|
 *
 * v0.1
 *
 * (c) 2013, fG! - reverser@put.as - http://reverse.put.as
 *
 * -> You are free to use this code as long as you maintain the original copyright <-
 *
 * A quick PoC TrustedBSD module to warn you if any app tries to write to system LaunchDaemons or LaunchAgents folders.
 *
 * MAC_POLICY_SET should be used instead of directly configuring the
 * kernel entry points. If this is used, duplicate symbol errors arise.
 * Most probably because I am using XCode's kernel extension template.
 *
 * Based on Sedarwin project sample policies code.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define VERSION "0.1"

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <security/mac_policy.h>
#include <sys/proc.h>
#include <string.h>
#include <sys/systm.h>
#include <stdbool.h> 
#include <sys/param.h>
#include <stdint.h>
#include <sys/vnode.h>
#include <sys/malloc.h>

static void
mac_ice_policy_initbsd(struct mac_policy_conf *conf)
{
	// nothing to do here...
}

/*
 * install a hook at write() syscall
 * here we can intercept calls to files we want to protect
 */
static int
mac_ice_policy_write(kauth_cred_t active_cred,
                     kauth_cred_t file_cred,
                     struct vnode *vp,
                     struct label *label)
{
    
	int error = 0;
	int retvalue = 0;
	// nothing to see
	if (vp == NULL) 
	{
		return (retvalue);
	}
	// get path retrieves the full path from the vnodes info without going to the filesystem
    char full_path[MAXPATHLEN+1];
    int fplen = MAXPATHLEN;
	error = vn_getpath(vp, full_path, &fplen);
    if (error) return 0;
    
    // the paths we want to monitor
    // all this code could be better :-]
    char ld[] = "/Library/LaunchDaemons";
    char la[] = "/Library/LaunchAgents";
    char sld[] = "/System/Library/LaunchDaemons";
    char sla[] = "/System/Library/LaunchAgents";
    
    if (strncmp(full_path, ld,  strlen(ld))  == 0 ||
        strncmp(full_path, sld, strlen(sld)) == 0 ||
        strncmp(full_path, la,  strlen(la))  == 0 ||
        strncmp(full_path, sla, strlen(la))  == 0)
    {
        char procname[MAXCOMLEN+1];
        int proclen = sizeof(procname);        
        // retrieve process name
        proc_selfname(procname, proclen);
        
        char alert_msg[1025];
        snprintf(alert_msg, sizeof(alert_msg), "Process \"%s\" is trying to write to LaunchDaemons or LaunchAgents folders.", procname);
        kern_return_t ret = KUNCUserNotificationDisplayNotice(10,		// Timeout
                                                              0,		// Flags
                                                              NULL,	// iconpath
                                                              NULL,	// soundpath
                                                              NULL,	// localization path
                                                              "Security Alert", // alert header
                                                              alert_msg, // alert message
                                                              "OK");	// button title
        return 0;
    }    
    return retvalue;
}

// register our handles
static struct mac_policy_ops mac_ice_ops =
{
	.mpo_policy_initbsd	= mac_ice_policy_initbsd,
    .mpo_vnode_check_write = mac_ice_policy_write,
};

static mac_policy_handle_t mac_ice_handle;

static struct mac_policy_conf ice_mac_policy_conf = {      
	.mpc_name               = "ice_the_guardianv2",                      
	.mpc_fullname           = "Ice The Guardian v2!",                   
	.mpc_labelnames         = NULL,                       
	.mpc_labelname_count    = 0,                       
	.mpc_ops                = &mac_ice_ops,                        
	.mpc_loadtime_flags     = MPC_LOADTIME_FLAG_UNLOADOK,     // modify this to 0 for "production" else this kernel module can be unloaded!
	.mpc_field_off          = NULL,                         
	.mpc_runtime_flags      = 0                        
};

// start the fun
kern_return_t
icetheguardian_start (kmod_info_t * ki, void * d) 
{
	return mac_policy_register(&ice_mac_policy_conf, &mac_ice_handle, d);
}

// stop the fun :-(
kern_return_t
icetheguardian_stop (kmod_info_t * ki, void * d) 
{
	return mac_policy_unregister(mac_ice_handle);
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

