run_test() {
    local thread_id=$1
    cargo run -- test_conf_client.json certificate.der identity.p12
}

for i in {1..10}; do
    run_test "$i" & 
done

echo "Main script: Waiting for all background tasks to complete..."
wait 
echo "Main script: All tasks finished successfully."