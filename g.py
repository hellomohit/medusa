import argparse
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--e', default='dev')
    # # app - stores the todo items
    # # users - stores the user data.
    parser.add_argument('-m', '--model',
        help='Specify which model do you want to create')
    args = parser.parse_args()
    print(args)
    # table_config = TABLES[args.table_type]
    # table_name = create(
    #     table_config['prefix'], table_config['hash_key'],
    #     table_config.get('range_key')
    # )
    # record_as_env_var(table_config['env_var'], table_name, args.stage)


if __name__ == '__main__':
    main()
