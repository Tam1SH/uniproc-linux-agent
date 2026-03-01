use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use libbpf_rs::OpenObject;
use ogurpchik::node::Node;
use ogurpchik::service_handler::ServiceHandler;
use ogurpchik::transport::stream::adapters::vsock::{VsockAddr, VsockTransport};
use tracing_subscriber::filter::LevelFilter;
use uniproc_protocol::{services, AgentCodec, AgentRequest, AgentResponse, ArchivedHostRequest, HostCodec, HostResponse};
use crate::bpf::BpfAgent;

mod bpf;
mod process_metrics_state;
mod iter_gc;
mod seed;
mod batch_lookup;
mod name_cache;

#[derive(Clone)]
struct GuestHandler {
    agent: Arc<Mutex<BpfAgent<'static>>>,
}

impl ServiceHandler<HostCodec> for GuestHandler {
    async fn on_request<'a>(&self, req: &ArchivedHostRequest) -> anyhow::Result<HostResponse> {
        match req {
            ArchivedHostRequest::GetReport => {
                let (processes, machine) = self.agent.lock().unwrap().collect()?;
                Ok(HostResponse::Report(uniproc_protocol::
                AgentReport {
                    machine,
                    processes,
                }))
            }
        }
    }
}


#[compio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();

    let open_object = Box::leak(Box::new(MaybeUninit::<OpenObject>::uninit()));
    let agent = Arc::new(Mutex::new(BpfAgent::init(open_object)?));

    let _guard = Node::new()?
        .serve::<HostCodec, _, _>(
            VsockTransport::server(VsockAddr::SelfManaged, 5000),
            GuestHandler { agent },
        )
        .publish(services::GUEST)
        .start()
        .await?;

    futures::future::pending::<()>().await;
    Ok(())
}