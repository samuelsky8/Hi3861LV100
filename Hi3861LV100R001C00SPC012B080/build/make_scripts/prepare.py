#!/usr/bin/env python3
# coding=utf-8

import os
import sys
import shutil
proj_top_dir = os.path.realpath(os.path.join(__file__, '..', '..', '..'))
print('proj_top_dir:',proj_top_dir)
sys.path.append(os.path.join(proj_top_dir, 'build'))
from scripts.scons_env_cfg import SconsEnvCfg as EnvCfg
from scripts.scons_utils import flag
from scripts.scons_utils import flag_r
from scripts.common_env import get_fixed_config
from scripts.common_env import get_make_str
from scripts import scons_app

def mkdir(path):
    isExists=os.path.exists(path)
    if not isExists:
        os.makedirs(path)
        print ('%s create success'% path)
        return True
    else:
        return False

def create_output_dirs(env_cfg):
    dir_list = [env_cfg.bin_path, env_cfg.log_path, env_cfg.cache_path, env_cfg.link_path]
    #env_cfg.obj_path, env_cfg.lib_path,
    [mkdir(x) for x in dir_list]

def transform_env_to_make(env, value):
    if env == 'CPPPATH':
        return 'INCLUDE := -I$(MAIN_TOPDIR)/%s\n'%(' \\\n\t-I$(MAIN_TOPDIR)/'.join(value))
    elif env == 'CPPDEFINES':
        defines = ['-D%s'%x for x in value if isinstance(x, str)]
        defines.extend(['-D%s=%s'%x for x in value if isinstance(x, tuple)])
        return 'DEFIENES := %s\n'%(' \\\n\t'.join(defines))
    else:
        item_value = ' '.join(value) if not isinstance(value, str) else value
        return '%s := %s\n'%(env.upper(), item_value)

def prepare_config_file(env_cfg):
    config_file = os.path.join(proj_top_dir, 'build', 'make_scripts', 'config.mk')
    with open(config_file, 'w+') as fp:
        modules = get_fixed_config('module')
        line = 'COMPILE_MODULE ?= %s\n'%(' '.join(modules))
        for module in modules:
            line = '%s%s_dir := %s\n'%(line, module, env_cfg.get_module_dir(module))
            libs = list(get_fixed_config('lib_cfg')[module].keys())
            line = '%s%s_libs := %s\n'%(line, module, ' '.join(libs))

        environs = env_cfg.get_makefile_environs()
        for item in environs:
            lineline = '%s%s'%(line, transform_env_to_make(item, environs[item]))

        line = '%s%s'%(line, get_make_str())
        line = '%sCCFLAGS += $(DEFIENES) $(INCLUDE)\n'%line
        fp.write(line)
#
def prepare_module_makefile(env_cfg):
    modules = env_cfg.get_all_modules()
    modules.extend(['boot', 'loaderboot'])
    for x in modules:
        dst_dir = os.path.join(proj_top_dir, env_cfg.get_module_dir(x))
        dst_makefile = os.path.join(dst_dir, 'Makefile')
        module_mk = os.path.join(dst_dir, 'module.mk')
        if not os.path.exists(module_mk):
            src_makefile = os.path.join(proj_top_dir, 'build', 'make_scripts', 'module.mk')
            shutil.copyfile(src_makefile, dst_makefile)
        else:
            shutil.move(module_mk, dst_makefile)
#
def prepare_module_lib_cfg(env_cfg, module):
    src_makefile = os.path.join(proj_top_dir, env_cfg.get_module_dir(module), 'module_config.mk')
    print('module:',module)
    if os.path.exists(src_makefile):
        return

    with open(src_makefile, 'w+') as fp:
        lib_cfg = get_fixed_config('lib_cfg')[module]
        line = ''
        for lib_name in lib_cfg:
            line = '%s%s_srcs := %s\n'%(line, lib_name, ' '.join(lib_cfg[lib_name]))

        for flg in flag:
            flg_cfg = env_cfg.get_module_cfg(module, flg, fixed=True)
            if flg_cfg is None:
                continue
            if flg == 'CPPDEFINES':
                defines = ['-D%s'%x for x in flg_cfg if isinstance(x, str)]
                defines.extend(['-D%s=%s'%x for x in flg_cfg if isinstance(x, tuple)])
                line = '%sCCFLAGS += %s\n'%(line, ' '.join(defines))
            elif flg == 'CPPPATH':
                line = '%sCCFLAGS += -I$(MAIN_TOPDIR)/%s\n'%(line, ' \\\n\t-I$(MAIN_TOPDIR)/'.join(flg_cfg))
            else:
                line = '%s%s += %s\n'%(line, flg, ' '.join(flg_cfg))

        module_cfg = get_make_str(module)
        line = '%s%s'%(line, module_cfg) if module_cfg is not None else line
        print('+++++++++++++++++\n',line)
        fp.write(line)
#
def do_prepare(env_cfg):
    create_output_dirs(env_cfg)
    #prepare_config_file(env_cfg)
    prepare_module_makefile(env_cfg)
    [prepare_module_lib_cfg(env_cfg, module) for module in env_cfg.get_all_modules()]



if __name__ == "__main__":
    args = len(sys.argv)
    print('++++++++++++++++++++++++++++++++++++++++PREPARE')
    env_cfg = EnvCfg()
    #app_builder = scons_app.AppTarget('demo')
    #env_cfg.set_app_builder(app_builder)
    do_prepare(env_cfg)
    
    #print('common str','+'*50)
    #print(get_make_str())
    #print('+'*50)
