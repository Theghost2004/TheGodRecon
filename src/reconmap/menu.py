"""Optional TTY-only guided access to the same CLI, never a second engine."""
from . import __version__


def menu():
    from .cli import main, parser, effective_config
    from .orchestrator import build_plan, print_plan, selected_names
    from .adapters import identify
    from .report_access import previous_runs, valid_report, open_report
    from .config import ConfigError
    while True:
        try:
            print(f'\n+--------- THEGODRECON {__version__} ---------+')
            print('1. Quick Scan\n2. Standard Scan\n3. Deep Scan\n4. Custom Scan (YAML)\n5. Run All Tools\n6. View Previous Reports\n7. Check Tool Health\n8. Setup / Repair Dependencies\n9. Help\n0. Exit')
            choice = input('Select an option: ').strip()
            if choice == '0':
                return 0
            if choice in {'1', '2', '3', '4', '5'}:
                target = input('Authorized target hostname or URL: ').strip()
                if not target:
                    print('Enter an explicit authorized target.')
                    continue
                values = ['scan', target]
                if choice == '4':
                    values += ['--config', input('Scope YAML path: ').strip()]
                elif choice == '5':
                    values += ['--all-tool']
                else:
                    values += ['--preset', {'1':'quick','2':'standard','3':'deep'}[choice]]
                args = parser().parse_args(values)
                config = effective_config(args)
                print_plan(build_plan(config, target, {n:identify(n,config.tools.get(n)) for n in selected_names(config)}))
                if input('Start within this scope and these budgets? [y/N] ').strip().lower() in {'y', 'yes'}:
                    main(values)
            elif choice == '6':
                runs = previous_runs()[:20]
                if not runs:
                    print('No valid reports found. Try reconmap demo.')
                    continue
                for number, run in enumerate(runs, 1):
                    print(f'{number}. {run}')
                selected = input('Report number (Enter to return): ').strip()
                if selected.isdigit() and 1 <= int(selected) <= len(runs):
                    open_report(valid_report(runs[int(selected)-1]))
            elif choice == '7':
                main(['doctor'])
            elif choice == '8':
                main(['setup'])
            elif choice == '9':
                parser().print_help()
            else:
                print('Choose an option from 0 to 9.')
        except EOFError:
            return 0
        except KeyboardInterrupt:
            print('\nCancelled. Returning to menu.')
        except (ConfigError, OSError, ValueError) as exc:
            print(f'Unable to continue: {exc}')
