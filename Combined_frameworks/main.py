import argparse
import subprocess
import sys

def main():
    
    parser = argparse.ArgumentParser(description="Run specific scripts based on framework or variant name.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--framework", help="Name of the framework (e.g., fig2dev, tcpdump, libsixel)")
    group.add_argument("--variant", help="Name of the variant (e.g., fig2dev_variant, tcpdump_variant, libsixel_variant)")

    args = parser.parse_args()

    framework_scripts = {
        "fig2dev": "fig2dev/fig2dev_tool.py",
        "tcpdump": "tcpdump/tcpdump_tool.py",
        "libsixel": "libsixel/libsixel_tool.py",
        "liblouis": "liblouis/liblouis_tool.py",
        "libtiff": "libtiff/libtiff_tool.py",
        "tensorflow": "tensorflow/tensorflow_tool.py",
        "zlib": "zlib_tool/zlib_tool.py",
        "yasm": "yasm/yasm_tool.py",
        "pytorch": "pytorch/pytorch_tool.py",
        "libsndfile": "libsndfile/libsndfile_tool.py",
        "binutils": "binutils/binutils_tool.py"

    }

    variant_scripts = {
        "fig2dev_variant": "fig2dev/fig2dev_variant_our/variant_own.py",
        "tcpdump_variant": "tcpdump/tcpdump_variant_our/variant_own.py",
        "libsixel_variant": "libsixel/libsixel_variant_our/variant_own.py",
        "liblouis_variant": "liblouis/liblouis_variant_our/variant_own.py",
        "libtiff_variant": "libtiff/libtiff_variant_our/variant_own.py",
        "tensorflow_variant": "tensorflow/tensorflow_variant_our/variant_own.py",
        "zlib_variant": "zlib_tool/zlib_variant_our/variant_own.py",
        "pytorch_variant": "pytorch/pytorch_variant_our/variant_own.py",
        "libsndfile_variant": "libsndfile/libsndfile_variant_our/variant_own.py",
        "yasm_variant": "yasm/yasm_variant_our/variant_own.py"
    }


    if args.framework:
        framework = args.framework.lower()

        # Check if the framework is supported
        if framework not in framework_scripts:
            print(f"Error: Unsupported framework '{framework}'.")
            print(f"Supported frameworks: {', '.join(framework_scripts.keys())}")
            sys.exit(1)

        target_script = framework_scripts[framework]
        command = ["python3", target_script]
        print(f"Executing Framework: {target_script}")

        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            print(f"\nError: The script {target_script} crashed or returned an error code: {e}")
        except FileNotFoundError:
            print(f"\nError: Could not find the file '{target_script}'. Ensure it exists in the same directory.")


    elif args.variant:
        framework_variant = args.variant.lower()

        # Check if the variant is supported
        if framework_variant not in variant_scripts:
            print(f"Error: Unsupported variant '{framework_variant}'.")
            print(f"Supported variants: {', '.join(variant_scripts.keys())}")
            sys.exit(1)

        target_variant = variant_scripts[framework_variant]
        command = ["python3", target_variant]
        print(f"Executing Variant: {target_variant}")

        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            print(f"\nError: The script {target_variant} crashed or returned an error code: {e}")
        except FileNotFoundError:
            print(f"\nError: Could not find the file '{target_variant}'. Ensure it exists in the same directory.")


if __name__ == "__main__":
    main()
