use crate::*;

pub struct Context {
    pub tau: u32,
    pub ed_key: ed25519::Keypair,

    pub params: Params,

    pub session_keypair: E::SessionKeypair,
    pub participants: Vec<Participant<E>>,
    pub vss: BTreeMap<u32, E::VSS>,
    pub domain: ark_poly::Radix2EvaluationDomain<E::Scalar>,
    pub state: DKGState<E>,
    pub me: usize,
    pub final_state: Option<DistributedKeyShares<E::Scalar>>,
}

impl<E> Context<E>
where
    E: Engine,
{
 

    pub fn handle_vss(
        &mut self,
        signer: &ed25519::PublicKey,
        dealing: &E::DealingMsg,
    ) -> Result<Option<SignedMessage>> {
    }

    pub fn handle_message(
        &mut self,
        msg: &SignedMessage,
    ) -> Result<Option<SignedMessage>> {
        let signer = &msg.signer;
        let msg: Message<E> = msg.verify()?;

  

        match msg.payload {
            MessagePayload::Announce { stake, session_key } => {
                self.handle_announce(signer, stake, session_key)
            }
            MessagePayload::VSS(vss) => self.handle_vss(signer, &vss),
            _ => E::handle_other(self, signer, &msg.payload),
        }
    }
}
if tau != msg_tau {
    return Err(anyhow!(
        "wrong tau={}, expected tau={}",
        msg.tau,
        self.tau
    ));
}
